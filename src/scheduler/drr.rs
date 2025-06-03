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
    logger: Option<csv::Writer<L>>,
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
    pub fn with_logger(self, w : L) -> Drr<HASH_PORTS,L> {
        self.maybe_with_logger(Some(w))
    }

    pub fn maybe_with_logger(self, w: Option<L>) -> Drr<HASH_PORTS, L> {
        Drr {
            limit_bytes: self.limit_bytes,
            queues: self.queues,
            curr_qsizes: self.curr_qsizes,
            deficits: self.deficits,
            quanta: self.quanta,
            queue_map: self.queue_map,
            num_queues: self.num_queues,
            deq_curr_qid: self.deq_curr_qid,

            logger: w.map(|x| csv::WriterBuilder::new().has_headers(false).from_writer(x)),
        }
        
    }
    pub fn log(&mut self){
        
        if let Some(log) = self.logger.as_mut() {
           /*  struct Flow <'a>{
                protocol: u8,
                source_ip: &'a str,
                dest_ip: &'a str,
                sport: u16,
                dport: u16
            }
            impl Serialize for Flow<'a> {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: Serializer,
                {
                    // 3 is the number of fields in the struct.
                    let mut state = serializer.serialize_struct("Flow", 5)?;
                    state.serialize_field("protocol", &self.protocol)?;
                    state.serialize_field("source_ip", &self.source_ip)?;
                    state.serialize_field("dest_ip", &self.dest_ip)?;
                    state.serialize_field("sport", &self.sport)?;
                    state.serialize_field("dport", &self.dport)?;
                    state.end()
                }
            }*/
                        
            #[derive(serde::Serialize)]
            struct Record{
                unix_time_ms: u128,
                queue_id: usize,
                queue_size: usize,
                flows_protocols: Vec<u8>,
                flows_source_ip: Vec<String>,
                flows_dest_ip: Vec<String>,
                flows_sport: Vec<u16>,
                flows_dport: Vec<u16>,
                
            }

            for i in 0..MAX_QUEUES{ // first fill out the vector
                let mut protocols:Vec<u8> = Vec::new();
                let mut source_ips:Vec<String> = Vec::new();
                let mut dest_ips:Vec<String> = Vec::new();
                let mut source_ports:Vec<u16> = Vec::new();
                let mut dest_ports:Vec<u16> = Vec::new();
                if self.curr_qsizes[i] > 0 {
                    for flow in self.queues[i].clone(){
                        protocols.push(flow.ip_hdr.protocol.0);
                        let source_ip = format!("{}.{}.{}.{}", flow.ip_hdr.source[0], flow.ip_hdr.source[1], flow.ip_hdr.source[2], flow.ip_hdr.source[3]);
                        source_ips.push(source_ip); 
                        let dest_ip = format!("{}.{}.{}.{}", flow.ip_hdr.destination[0], flow.ip_hdr.destination[1], flow.ip_hdr.destination[2], flow.ip_hdr.destination[3]);
                        dest_ips.push(dest_ip);
                        source_ports.push(flow.sport);
                        dest_ports.push(flow.dport);
                    }
                    if let Err(err) = log.serialize(Record {
                        unix_time_ms: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis(),
                        queue_id:i,
                        queue_size:self.curr_qsizes[i],
                        flows_protocols: protocols,
                        flows_source_ip: source_ips,
                        flows_dest_ip: dest_ips,
                        flows_sport: source_ports,
                        flows_dport: dest_ports,
                        
                    }) {
                        debug!(?err, "write to logger failed");
                    }
                } 
                
                

            }
            
        }
        debug!(?self.curr_qsizes, ?self.queue_map, "rate counter log");


    }
}


#[cfg(feature = "drr-argparse")]
pub mod parse_args {
    use std::{path::PathBuf, str::FromStr};
    use clap::Parser;
    use color_eyre::eyre::Report;
    use super::Drr;
    #[derive(Parser, Debug)]
    #[command(name = "drr")]
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

    
   

    
}





