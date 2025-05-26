use super::Scheduler;
use crate::{Error, Pkt};
use color_eyre::eyre::{ensure, Report};
use std::time::Duration;
use std::collections::{hash_map::Entry, HashMap, VecDeque};
use tracing::debug;

// Define constant max number of queues.
const MAX_QUEUES: usize = 32;

const FNV1_64_INIT: u64 = 0xcbf29ce484222325u64;
const FNV_64_PRIME: u64 = 0x100000001b3u64;
fn fnv_ips(src: [u8; 4], dst: [u8; 4], queues: u64) -> u8 {
    let mut hash = FNV1_64_INIT;
    for b in src.iter().chain(dst.iter()) {
        hash ^= *b as u64;
        hash = u64::wrapping_mul(hash, FNV_64_PRIME);
    }

    (hash % queues) as u8
}

fn fnv_ports(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, queues: u64) -> u8 {
    let mut hash = FNV1_64_INIT;
    for b in src
        .iter()
        .chain(dst.iter())
        .chain(sport.to_be_bytes().iter())
        .chain(dport.to_be_bytes().iter())
    {
        hash ^= *b as u64;
        hash = u64::wrapping_mul(hash, FNV_64_PRIME);
    }

    (hash % queues) as u8
}

#[derive(Default)]
pub struct Drr<const HASH_PORTS: bool, L: std::io::Write>{
    limit_bytes: usize,
    queues: [VecDeque<Pkt>; MAX_QUEUES],
    curr_qsizes: [usize; MAX_QUEUES],
    deficits: [usize; MAX_QUEUES],
    quanta: [usize; MAX_QUEUES],

    queue_map: HashMap<u8, usize>,
    num_queues: usize,

    deq_curr_qid: usize,
    logger: Option<csv::Writer<L>>
}

impl<const HASH_PORTS: bool, W: std::io::Write>  Drr<HASH_PORTS , W> {
    pub fn new(limit_bytes: usize) ->  Result<Self, Report> {
        Ok(
        Self {
            limit_bytes:limit_bytes,
            queues: Default::default(),
            curr_qsizes: [0usize; MAX_QUEUES],
            deficits: [0usize; MAX_QUEUES],
            quanta: [500usize; MAX_QUEUES],
            queue_map: HashMap::new(),
            num_queues: 0,
            deq_curr_qid: 0,
            logger: None,
        })
    }
}

impl<const HASH_PORTS: bool, L: std::io::Write> Scheduler for Drr<HASH_PORTS, L> {
    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        let curr_tot_qsize: usize = self.curr_qsizes.iter().sum();
        ensure!(
            curr_tot_qsize + p.buf.len() <= self.limit_bytes,
            Error::PacketDropped(p)
        );

        // hash p into a queue
        let flow_id = if HASH_PORTS {
            fnv_ports(
                p.ip_hdr.source,
                p.ip_hdr.destination,
                p.sport,
                p.dport,
                MAX_QUEUES as u64,
            )
        } else {
            fnv_ips(p.ip_hdr.source, p.ip_hdr.destination, MAX_QUEUES as u64)
        };

        match self.queue_map.entry(flow_id) {
            Entry::Occupied(entry) => {
                let queue_id = entry.get();
                self.curr_qsizes[*queue_id] += p.buf.len();
                self.queues[*queue_id].push_back(p);
                Ok(())
            }
            Entry::Vacant(entry) => {
                assert!(self.num_queues < MAX_QUEUES);
                entry.insert(self.num_queues);
                let queue_id = self.num_queues;
                self.num_queues += 1;
                self.curr_qsizes[queue_id] += p.buf.len();
                self.queues[queue_id].push_back(p);
                Ok(())
            }
        }
    }

    fn deq(&mut self) -> Result<Option<Pkt>, Report> {
        let curr_tot_qsize: usize = self.curr_qsizes.iter().sum();
        if curr_tot_qsize == 0 {
            return Ok(None);
        }

        loop {
            if !self.queues[self.deq_curr_qid].is_empty() {
                // see if there are any packets big enough to fit the accrued deficit.
                // unwraps ok because we know the queue is not empty.
                if self.deficits[self.deq_curr_qid]
                    > self.queues[self.deq_curr_qid].front().unwrap().buf.len()
                {
                    let p = self.queues[self.deq_curr_qid].pop_front().unwrap();
                    if self.queues[self.deq_curr_qid].is_empty() {
                        self.deficits[self.deq_curr_qid] = 0;
                    } else {
                        self.deficits[self.deq_curr_qid] -= p.buf.len();
                    }

                    self.curr_qsizes[self.deq_curr_qid] -= p.buf.len();
                    return Ok(Some(p));
                }

                // increment the deficit.
                // CAREFUL: this must come *after* the check above, otherwise we will only service
                // one queue by giving it deficit increments right before we try to send on it.
                // This is the opposite of the algorithm on wikipedia
                // (https://en.wikipedia.org/wiki/Deficit_round_robin), which does not have to
                // worry about returning and just sends inside an inner loop.
                self.deficits[self.deq_curr_qid] += self.quanta[self.deq_curr_qid];
            }

            self.deq_curr_qid = (self.deq_curr_qid + 1) % self.queues.len();
        }
    }

    fn len_bytes(&self) -> usize {
        self.curr_qsizes.iter().sum()
    }

    fn len_packets(&self) -> usize {
        self.queues.iter().map(VecDeque::len).sum()
    }

    fn is_empty(&self) -> bool {
        self.curr_qsizes.iter().all(|x| *x == 0)
    }

    fn set_max_len_bytes(&mut self, bytes: usize) -> Result<(), Report> {
        self.limit_bytes = bytes;
        Ok(())
    }
    fn dbg(&mut self, _epoch_dur: Duration) {
        self.log()
        
    }

    
}


impl<const HASH_PORTS: bool, L: std::io::Write> Drr<HASH_PORTS, L> {
    pub fn with_logger<const HASH_TWO:bool, W: std::io::Write>(self, w: W) -> Drr<HASH_TWO,W> {
        self.maybe_with_logger(Some(w))
    }

    pub fn maybe_with_logger<const HASH_TWO:bool , W: std::io::Write>(self, w: Option<W>) -> Drr<HASH_TWO, W> {
        Drr {
            limit_bytes: self.limit_bytes,
            queues: self.queues,
            curr_qsizes: self.curr_qsizes,
            deficits: self.deficits,
            quanta: self.quanta,
            queue_map: self.queue_map,
            num_queues: self.num_queues,
            deq_curr_qid: self.deq_curr_qid,

            logger: w.map(|x| csv::Writer::from_writer(x)),
        }
    }
        fn log(&mut self){
        if let Some(log) = self.logger.as_mut() {
            #[derive(serde::Serialize)]
            struct Record {
                unix_time_ms: u128,
                curr_qsizes: [usize; MAX_QUEUES],
                queue_map: HashMap<u8, usize>,
            }

            if let Err(err) = log.serialize(Record {
                unix_time_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
                
                curr_qsizes: self.curr_qsizes,
                queue_map: self.queue_map.clone(),
            }) {
                debug!(?err, "write to logger failed");
            }
        }
        debug!(?self.curr_qsizes, ?self.queue_map, "rate counter log");


    }
}


#[cfg(feature = "drr-argparse")]
pub mod parse_args {
    use std::{path::PathBuf, str::FromStr};

    use clap::Parser;
    use color_eyre::eyre::{eyre, Report};
    use super::Drr;
    #[derive(Parser, Debug)]
    #[command(name = "hwfq")]
    pub struct Opt {
        #[arg(short, long)]
        pub limit_bytes: usize,

        #[arg(long)]
        pub log_file: Option<PathBuf>,

        
    }

    impl <const HASH_PORTS: bool>  FromStr for Drr<HASH_PORTS, std::fs::File> {
        type Err = Report;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let sp = s.split_whitespace();
            let dummy = std::iter::once("tmp");
            let opt = Opt::try_parse_from(dummy.chain(sp))?;
            opt.try_into()
        }
    }

    impl <const HASH_PORTS: bool> TryFrom<Opt> for Drr<HASH_PORTS,std::fs::File > {
        type Error = Report;
        fn try_from(o: Opt) -> Result<Self, Self::Error> {
            Ok(Drr::< HASH_PORTS, std::fs::File>::new(
                o.limit_bytes,
            )?
            .maybe_with_logger(o.log_file.map(std::fs::File::create).transpose()?))
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub struct ClassOpt {
        dport: u16,
        rate: usize,
    }

    impl FromStr for ClassOpt {
        type Err = Report;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let mut sp = s.split('=');
            let dport = sp
                .next()
                .ok_or_else(|| eyre!("dport=rate format for class"))?
                .parse()?;
            let rate = sp
                .next()
                .ok_or_else(|| eyre!("dport=rate format for class"))?
                .parse()?;
            Ok(ClassOpt { dport, rate })
        }
    }

   

    
}





