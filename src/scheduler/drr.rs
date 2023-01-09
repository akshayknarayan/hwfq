use super::{fnv, Scheduler};
use crate::Pkt;
use color_eyre::eyre::{ensure, Report};
use std::collections::VecDeque;

#[derive(Default)]
pub struct Drr {
    limit_bytes: usize,
    queues: [VecDeque<Pkt>; 8],
    curr_qsizes: [usize; 8],
    deficits: [usize; 8],
    quanta: [usize; 8],

    deq_curr_qid: usize,
}

impl Drr {
    pub fn new(limit_bytes: usize) -> Self {
        Self {
            limit_bytes,
            queues: Default::default(),
            curr_qsizes: [0usize; 8],
            deficits: [0usize; 8],
            quanta: [500usize; 8],
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
            self.queues.len() as _,
        );
        let queue_id = (flow_id % self.queues.len() as u8) as usize;
        self.curr_qsizes[queue_id] += p.buf.len();
        self.queues[queue_id].push_back(p);
        Ok(())
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
