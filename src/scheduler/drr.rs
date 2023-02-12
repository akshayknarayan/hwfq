use super::{fnv, Scheduler};
use crate::Pkt;
use color_eyre::eyre::{ensure, Report};
use std::collections::{VecDeque, HashMap};

// Define constant max number of queues.
const MAX_QUEUES: usize = 32;

#[derive(Default)]
pub struct Drr {
    limit_bytes: usize,
    queues: [VecDeque<Pkt>; MAX_QUEUES],
    curr_qsizes: [usize; MAX_QUEUES],
    deficits: [usize; MAX_QUEUES],
    quanta: [usize; MAX_QUEUES],

    queue_map: HashMap<u8, usize>,
    num_queues: usize,

    deq_curr_qid: usize,
}

impl Drr {
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

impl Scheduler for Drr {
    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        let curr_tot_qsize: usize = self.curr_qsizes.iter().sum();
        ensure!(
            curr_tot_qsize + p.buf.len() <= self.limit_bytes,
            "Dropping packet"
        );

        // hash p into a queue
        let flow_id = fnv(
            p.ip_hdr.source,
            p.ip_hdr.destination,
            MAX_QUEUES as u64,
        );
        if self.queue_map.contains_key(&flow_id) {
            let queue_id = self.queue_map.get(&flow_id).unwrap();
            self.curr_qsizes[*queue_id] += p.buf.len();
            self.queues[*queue_id].push_back(p);
            return Ok(());
        } else {
            assert !(self.num_queues >= MAX_QUEUES);
            self.queue_map.insert(flow_id, self.num_queues);
            self.num_queues += 1;
            let queue_id = self.queue_map.get(&flow_id).unwrap();
            self.curr_qsizes[*queue_id] += p.buf.len();
            self.queues[*queue_id].push_back(p);
            return Ok(());
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
}
