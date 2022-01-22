use super::Pkt;
use color_eyre::eyre::{ensure, Report};
use std::collections::VecDeque;
use tracing::trace;

pub trait Scheduler {
    /// Enqueue a packet into the scheduler's queue.
    ///
    /// Return true if the queue was empty before this packet was added, signifying that the
    /// dequeue thread should wake up and start dequeueing packets.
    fn enq(&mut self, p: Pkt) -> Result<bool, Report>;

    /// Dequeue a packet from the scheduler's queue.
    ///
    /// Return `None` if the queue is empty and the dequeue thread should therefore go to sleep,
    /// and `Some(dequeued_packet)` otherwise.
    fn deq(&mut self) -> Result<Option<Pkt>, Report>;
}

pub struct Fifo {
    limit_bytes: usize,
    cur_qsize_bytes: usize,
    inner: VecDeque<Pkt>,
}

impl Fifo {
    pub fn new(limit_bytes: usize) -> Self {
        Self {
            limit_bytes,
            cur_qsize_bytes: 0,
            inner: Default::default(),
        }
    }
}

impl Scheduler for Fifo {
    fn enq(&mut self, p: Pkt) -> Result<bool, Report> {
        let now_active = self.inner.is_empty();
        let new_qsize_bytes = self.cur_qsize_bytes + p.buf.len();
        ensure!(new_qsize_bytes <= self.limit_bytes, "Dropping packet");
        self.cur_qsize_bytes = new_qsize_bytes;
        self.inner.push_back(p);
        trace!(pkts=?self.inner.len(), "queue size");
        Ok(now_active)
    }

    fn deq(&mut self) -> Result<Option<Pkt>, Report> {
        match self.inner.pop_front() {
            Some(p) => {
                self.cur_qsize_bytes -= p.buf.len();
                Ok(Some(p))
            }
            None => Ok(None),
        }
    }
}

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
            quanta: [1500usize; 8],
            deq_curr_qid: 0,
        }
    }
}

const FNV1_64_INIT: u64 = 0xcbf29ce484222325u64;
const FNV_64_PRIME: u64 = 0x100000001b3u64;

fn fnv(src: [u8; 4], dst: [u8; 4], queues: u64) -> u8 {
    let mut hash = FNV1_64_INIT;
    for b in src.iter().chain(dst.iter()) {
        hash ^= *b as u64;
        hash = u64::wrapping_mul(hash, FNV_64_PRIME);
    }

    (hash % queues as u64) as u8
}

impl Scheduler for Drr {
    fn enq(&mut self, p: Pkt) -> Result<bool, Report> {
        let curr_tot_qsize: usize = self.curr_qsizes.iter().sum();
        let now_active = curr_tot_qsize == 0;
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
        Ok(now_active)
    }

    fn deq(&mut self) -> Result<Option<Pkt>, Report> {
        let start_qid = self.deq_curr_qid;
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

                // increment the quanta.
                // CAREFUL: this must come *after* the check above, otherwise we will only service
                // one queue by giving it deficit increments right before we try to send on it.
                // This is the opposite of the algorithm on wikipedia
                // (https://en.wikipedia.org/wiki/Deficit_round_robin), which does not have to
                // worry about returning and just sends inside an inner loop.
                self.deficits[self.deq_curr_qid] += self.quanta[self.deq_curr_qid];
            }

            self.deq_curr_qid = (self.deq_curr_qid + 1) % self.queues.len();
            // if we went through all the queues without returning, then we say there are no
            // packets.
            if self.deq_curr_qid == start_qid {
                return Ok(None);
            }
        }
    }
}
