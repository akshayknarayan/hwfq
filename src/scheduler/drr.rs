use super::Scheduler;
use crate::{Error, Pkt};
use color_eyre::eyre::{ensure, Report};
use std::collections::{hash_map::Entry, HashMap, VecDeque};

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
pub struct Drr<const HASH_PORTS: bool> {
    limit_bytes: usize,
    queues: [VecDeque<Pkt>; MAX_QUEUES],
    curr_qsizes: [usize; MAX_QUEUES],
    deficits: [usize; MAX_QUEUES],
    quanta: [usize; MAX_QUEUES],

    queue_map: HashMap<u8, usize>,
    num_queues: usize,

    deq_curr_qid: usize,
}

impl<const HASH_PORTS: bool> Drr<HASH_PORTS> {
    pub fn new(limit_bytes: usize) -> Self {
        Self {
            limit_bytes,
            queues: Default::default(),
            curr_qsizes: [0usize; MAX_QUEUES],
            deficits: [0usize; MAX_QUEUES],
            quanta: [500usize; MAX_QUEUES],
            queue_map: HashMap::new(),
            num_queues: 0,
            deq_curr_qid: 0,
        }
    }
}

impl<const HASH_PORTS: bool> Scheduler for Drr<HASH_PORTS> {
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
}
