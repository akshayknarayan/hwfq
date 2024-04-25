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

mod fifo;
pub use fifo::Fifo;

mod drr;
pub use drr::Drr;

#[cfg(any(feature = "htb", feature = "afd", feature = "hdwrr"))]
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
