use super::Pkt;
use color_eyre::eyre::{ensure, Report};
use std::collections::VecDeque;

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
