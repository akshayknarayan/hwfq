use super::Scheduler;
use crate::{Error, Pkt};
use color_eyre::eyre::{ensure, Report};
use log::debug;
use std::collections::{hash_map::Entry, HashMap, VecDeque};
use std::time::Duration;

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
pub struct Drr<const HASH_PORTS: bool, L: std::io::Write> {
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

impl<const HASH_PORTS: bool, W: std::io::Write> Drr<HASH_PORTS, W> {
    pub fn new(limit_bytes: usize) -> Result<Self, Report> {
        Ok(Self {
            limit_bytes: limit_bytes,
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
        let mut curr_tot_qsize: usize = 0;
        for i in 0..32 {
            curr_tot_qsize += self.queues[i].len();
        }
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
    pub fn with_logger(self, w: L) -> Drr<HASH_PORTS, L> {
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
    pub fn log(&mut self) {
        if let Some(log) = self.logger.as_mut() {
            #[derive(serde::Serialize)]
            struct Record {
                unix_time_ms: u128,
                queue_id: usize,
                queue_size: usize,
                flows: Vec<String>,
            }

            for i in 0..MAX_QUEUES {
                // first fill out the vector
                let mut flows: Vec<String> = Vec::new();
                if self.curr_qsizes[i] > 0 {
                    let old_flows = self.queues[i].clone().into_iter();
                    for flow in old_flows {
                        if let Some(prot) = flow.ip_hdr.protocol.keyword_str() {
                            let output: String = format!("({}:", prot) + 
                            format!("{}.{}.{}.{} -> ", flow.ip_hdr.source[0], flow.ip_hdr.source[1], flow.ip_hdr.source[2], flow.ip_hdr.source[3]).as_mut_str() +  //source ip
                            format!("{}.{}.{}.{}, ", flow.ip_hdr.destination[0], flow.ip_hdr.destination[1], flow.ip_hdr.destination[2], flow.ip_hdr.destination[3]).as_mut_str() + //dest ip
                            format!("{} -> {})\n", flow.sport, flow.dport).as_mut_str();
                            flows.push(output);
                        }
                    }
                    if let Err(err) = log.serialize(Record {
                        unix_time_ms: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis(),
                        queue_id: i,
                        queue_size: self.queues[i].len(),
                        flows: flows,
                    }) {
                        debug!("{} write to logger failed", err);
                    }
                }
            }
        }
        //  debug!("{} {} rate counter log", self.curr_qsizes);
    }
}

#[cfg(feature = "drr-argparse")]
pub mod parse_args {
    use super::Drr;
    use clap::Parser;
    use color_eyre::eyre::Report;
    use std::{path::PathBuf, str::FromStr};
    #[derive(Parser, Debug)]
    #[command(name = "drr")]
    pub struct Opt {
        #[arg(short, long)]
        pub limit_bytes: usize,

        #[arg(long)]
        pub log_file: Option<PathBuf>,
    }

    impl<const HASH_PORTS: bool> FromStr for Drr<HASH_PORTS, std::fs::File> {
        type Err = Report;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let sp = s.split_whitespace();
            let dummy = std::iter::once("tmp");
            let opt = Opt::try_parse_from(dummy.chain(sp))?;
            opt.try_into()
        }
    }

    impl<const HASH_PORTS: bool> TryFrom<Opt> for Drr<HASH_PORTS, std::fs::File> {
        type Error = Report;
        fn try_from(o: Opt) -> Result<Self, Self::Error> {
            Ok(Drr::<HASH_PORTS, std::fs::File>::new(o.limit_bytes)?
                .maybe_with_logger(o.log_file.map(std::fs::File::create).transpose()?))
        }
    }

    #[cfg(test)]
    mod t {
        use crate::scheduler::drr::DeficitRoundRobin;

        #[test]
        fn parse_test() {
            let args = "--limit-bytes=120000";
            let sp: Vec<_> = args.split_whitespace().collect();
            dbg!(sp);
            let x: DeficitRoundRobin<_> = args.parse().unwrap();
            assert_eq!(x.limit_bytes, 120000);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use quanta::Instant;

    use crate::scheduler::Scheduler;

    use super::Drr;

    fn enq_deq_packets<const HASH_PORTS: bool, L: std::io::Write>(
        mut s: Drr<HASH_PORTS, L>,
        dports: Vec<u16>,        // the different queues
        num_packets: Vec<usize>, // number of packets each queue to have different number of flows
    ) -> (Duration, Duration, Vec<usize>) {
        let src_ip = [42, 2, 0, 0];
        let d_ip = [42, 1, 2, 6];
        // if the flow's impact is zero it shouldn't be included
        if dports.len() != num_packets.len() {
            dbg!(dports.len(), num_packets.len(), "These should be equal");
            return (Duration::ZERO, Duration::ZERO, Vec::new()); // need to add a check for this
        }
        let enq_start = Instant::now();
        let call_less = num_packets.len();
        // create packets for each queue
        for i in 0..call_less {
            for _ in 0..num_packets[i] {
                s.enq(crate::Pkt {
                    ip_hdr: etherparse::Ipv4Header::new(
                        100,
                        64,
                        etherparse::IpNumber::TCP,
                        src_ip,
                        d_ip,
                    )
                    .unwrap(),
                    dport: dports[i % dports.len()],
                    sport: 4242,
                    buf: vec![],
                    fake_len: 1500,
                })
                .expect("enqueue dummy packet");
            }
        }
        let enq_elapsed = enq_start.elapsed();

        let mut cnt_vec = Vec::new();
        for _ in 0..dports.len() {
            cnt_vec.push(0);
        }
        let mut d_cnt = 0;

        let mut el: Duration = Duration::ZERO;
        while el < Duration::from_millis(1_000) {
            // only measures deque timing, not searching through list's timing
            let start = Instant::now(); 
            let p = match s.deq().expect("dequeue") {
                None => {
                    cnt_vec.push(d_cnt);
                    return (start.elapsed(), enq_elapsed, cnt_vec);
                }
                Some(a) => a,
            };
            el += start.elapsed();
            // checks if we need to put it into dport without having to run through the vector twice
            let mut changed: bool = false;
            for i in 0..dports.len() {
                if p.dport == dports[i] {
                    changed = true;
                    cnt_vec[i] += p.len();
                }
            }
            if !changed {
                d_cnt += p.len();
            }
        }
        cnt_vec.push(d_cnt);
        // the(unused) first two outputs kept to be able to later test enqueing and dequeing's individual rates later
        (el, enq_elapsed, cnt_vec) 
    }

    #[test]
    fn basic() {
        let runner: Drr<true, std::io::Empty> = Drr::new(12000).unwrap();
        let (el, enq_el, v) = enq_deq_packets(runner, vec![4242, 4243], vec![300, 300]);
        let c1_cnt = v[0];
        let c2_cnt = v[1];
        let d_cnt = v[2];

        let tot = c1_cnt + c2_cnt + d_cnt;
        dbg!(c1_cnt, c2_cnt);

        // actual test (other tests don't follow this format at all, this only works because these are supposed to be near-equal to each other)
        assert!(
            (((c1_cnt as f64) - (c2_cnt as f64)) / tot as f64).abs() < 0.01,
            "class1 rate error off by more than 1%"
        );
    }
    #[test]
    fn three() { //testing 3 equal number of packets sents
        let runner: Drr<true, std::io::Empty> = Drr::new(12000).unwrap();
        let rates = vec![300, 300, 300];
        let (_, _, v) = enq_deq_packets(runner, vec![4242, 4243, 4244], rates.clone());

        let tot: usize = v.iter().sum();
        let pack_tot: usize = rates.iter().sum();

        //dbg!(c1_cnt, c2_cnt);

        //the different flows should all have relatively similar dequeue rates
        for i in 0..rates.len() {
            assert!(
                (((v[i] as f64) / tot as f64) - rates[i] as f64 / pack_tot as f64).abs() < 0.01,
                "class1 rate error off by more than 1%"
            );
        }
    }
    #[test]
    fn diff_rates() { // testing 2 unequal number of packets sent
        let runner: Drr<true, std::io::Empty> = Drr::new(12000).unwrap();
        let rates = vec![1500, 750];
        let (_, _, v) = enq_deq_packets(runner, vec![4242, 4243], rates.clone());

        let tot: usize = v.iter().sum();
        let pack_tot: usize = rates.iter().sum();

        //dbg!(c1_cnt, c2_cnt);

        //the different flows should all have relatively similar dequeue rates
        for i in 0..rates.len() {
            dbg!(i);
            assert!(
                (((v[i] as f64) / tot as f64) - (rates[i] as f64 / pack_tot as f64)).abs() < 0.01,
                "class1 rate error off by more than 1%"
            );
        }
    }
    #[test]
    fn three_diff_rates() { //testing 3 distinct number of packets sent
        let runner: Drr<true, std::io::Empty> = Drr::new(12000).unwrap();
        let rates = vec![300, 150, 800];
        let (_, _, v) = enq_deq_packets(runner, vec![4242, 4243, 4244], rates.clone());

        let tot: usize = v.iter().sum();
        let pack_tot: usize = rates.iter().sum();

        //dbg!(c1_cnt, c2_cnt);

        //the different flows should all have relatively similar dequeue rates
        for i in 0..rates.len() {
            assert!(
                (((v[i] as f64) / tot as f64) - rates[i] as f64 / pack_tot as f64).abs() < 0.01,
                "class1 rate error off by more than 1%"
            );
        }
        dbg!("hello");
    }
    #[test]
    fn high_rates() { // testing 3 different number of packets that (i think) should be over the limit
        let runner: Drr<true, std::io::Empty> = Drr::new(12000).unwrap();
        let rates = vec![30000, 150, 80000];
        let (_, _, v) = enq_deq_packets(runner, vec![4242, 4243, 4244], rates.clone());

        let tot: usize = v.iter().sum();
        let pack_tot: usize = rates.iter().sum();

        //dbg!(c1_cnt, c2_cnt);

        //the different flows should all have relatively similar dequeue rates
        for i in 0..rates.len() {
            assert!(
                (((v[i] as f64) / tot as f64) - rates[i] as f64 / pack_tot as f64).abs() < 0.01,
                "class1 rate error off by more than 1%"
            );
        }
        dbg!("hello");
    }
    #[test]
    fn low_rates() { // testing 3 different number of packets, one of which is 0 packets
        let runner: Drr<true, std::io::Empty> = Drr::new(12000).unwrap();
        let rates = vec![0, 1, 3];
        let (_, _, v) = enq_deq_packets(runner, vec![4242, 4243, 4244], rates.clone());

        let tot: usize = v.iter().sum();
        let pack_tot: usize = rates.iter().sum();

        //dbg!(c1_cnt, c2_cnt);

        //the different flows should all have relatively similar dequeue rates
        for i in 0..rates.len() {
            assert!(
                (((v[i] as f64) / tot as f64) - rates[i] as f64 / pack_tot as f64).abs() < 0.01,
                "class1 rate error off by more than 1%"
            );
        }
    }
}
