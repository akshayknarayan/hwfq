use std::time::Duration;

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

    /// Set the maximum length of the scheduler's queue in bytes.
    fn set_max_len_bytes(&mut self, bytes: usize) -> Result<(), Report>;

    /// The current length of the scheduler's queue in bytes.
    fn len_bytes(&self) -> usize;

    /// The current length of the scheduler's queue in packets.
    ///
    /// Note: Packets are not necessarily constant size, so this is not always the same information
    /// as [`Scheduler::len_bytes()`].
    fn len_packets(&self) -> usize;

    /// Whether the scheduler's queue is currently empty.
    ///
    /// If this returns `true`, `deq` *must* return either `Ok(None)` or `Err(_)`.
    fn is_empty(&self) -> bool {
        self.len_packets() == 0
    }

    /// Called periodically when it is time to dump debug info logs.
    fn dbg(&mut self, _epoch_dur: Duration) {}
}

mod fifo;
pub use fifo::Fifo;

#[cfg(feature ="drr")]
pub mod drr;

#[cfg(any(feature = "afd", feature = "hdwrr"))]
pub mod weight_tree;

#[cfg(feature = "htb")]
pub mod htb;

#[cfg(feature = "hdwrr")]
mod hdwrr;
#[cfg(feature = "hdwrr")]
pub use hdwrr::HierarchicalDeficitWeightedRoundRobin;

#[cfg(feature = "afd")]
mod afd;
#[cfg(feature = "afd")]
mod hafd;
#[cfg(feature = "afd")]
mod wafd;

#[cfg(feature = "afd")]
pub use {
    afd::ApproximateFairDropping, hafd::HierarchicalApproximateFairDropping,
    wafd::WeightedApproximateFairDropping,
};
