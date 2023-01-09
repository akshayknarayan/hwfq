use super::Scheduler;
use crate::Pkt;
use color_eyre::eyre::{ensure, Report};
use std::collections::VecDeque;
use tracing::trace;

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
    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        let new_qsize_bytes = self.cur_qsize_bytes + p.buf.len();
        ensure!(new_qsize_bytes <= self.limit_bytes, "Dropping packet");
        self.cur_qsize_bytes = new_qsize_bytes;
        self.inner.push_back(p);
        trace!(pkts=?self.inner.len(), "queue size");
        Ok(())
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
