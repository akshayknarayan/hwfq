use super::Pkt;
use color_eyre::eyre::Report;

/// Expose a pluggable scheduler implementation to [`crate::Datapath`].
pub trait Scheduler {
    /// Enqueue a packet into the scheduler's queue.
    ///
    /// Return true if the queue was empty before this packet was added, signifying that the
    /// dequeue thread should wake up and start dequeueing packets.
    fn enq(&mut self, p: Pkt) -> Result<(), Report>;

    /// Dequeue a packet from the scheduler's queue.
    ///
    /// Return `None` if the queue is empty and the dequeue thread should therefore go to sleep,
    /// and `Some(dequeued_packet)` otherwise.
    fn deq(&mut self) -> Result<Option<Pkt>, Report>;

    /// Called periodically when it is time to dump debug info logs.
    fn dbg(&self) {}
}

pub mod common;

mod fifo;
pub use fifo::Fifo;

mod drr;
pub use drr::Drr;

mod hdwrr;
pub use hdwrr::HierarchicalDeficitWeightedRoundRobin;

mod afd;
pub use afd::ApproximateFairDropping;

mod wafd;
pub use wafd::WeightedApproximateFairDropping;

mod hafd;
pub use hafd::HierarchicalApproximateFairDropping;

fn fnv(src: [u8; 4], dst: [u8; 4], queues: u64) -> u8 {
    const FNV1_64_INIT: u64 = 0xcbf29ce484222325u64;
    const FNV_64_PRIME: u64 = 0x100000001b3u64;

    let mut hash = FNV1_64_INIT;
    for b in src.iter().chain(dst.iter()) {
        hash ^= *b as u64;
        hash = u64::wrapping_mul(hash, FNV_64_PRIME);
    }

    (hash % queues) as u8
}
