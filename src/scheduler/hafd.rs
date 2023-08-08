use super::Scheduler;
use crate::Pkt;
use color_eyre::eyre::{ensure, Report};
#[cfg(feature = "hwfq-audit")]
use std::collections::HashMap;
use std::collections::VecDeque;
use tracing::debug;
use crate::scheduler::common::WeightTree;
use crate::scheduler::common::MAX_NUM_CHILDREN;
use crate::scheduler::common::parse_ip;

fn get_aggregates(packet: Pkt) -> Vec<String> {
    // TODO: Implement this.
    vec![]
}

pub struct ShadowBuffer {
    packet_sample_prob: f64,
    max_packets: usize,
    inner: VecDeque<Pkt>
}

impl ShadowBuffer {
    pub fn new(max_packets: usize) -> Self {
        Self {
            max_packets,
            inner: Default::default(),
        }
    }

    pub fn sample(&mut self, p: Pkt) -> Result<(), Report> {
        if rand::random::<f64>() < self.packet_sample_prob {
            self.enq(p)?;
        }
        Ok(())
    }

    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        // If we are at capacity pop the oldest packet.
        if self.inner.len() == self.max_packets {
            self.inner.pop_front();
        }
        self.inner.push_back(p);
        Ok(())
    }

    /// Returns an updated aggregate occupancy table, which maps from an aggregate to its count inside the shadow buffer.
    pub fn get_aggregate_occupancy(&self) -> HashMap<String, usize> {
        let mut aggregate_stats = HashMap::new();
        for p in &self.inner {
            let aggregates = get_aggregates(p.clone());
            for aggregate in aggregates {
                let count = aggregate_stats.entry(aggregate).or_insert(0);
                *count += 1;
            }
        }
        aggregate_occupancy
    }
}

/// Implement a hierarchical deficit round-robin [`Scheduler`].
///
/// See [`HierarchicalDeficitWeightedRoundRobin::new`].
#[derive(Debug)]
pub struct HierarchicalApproximateFairDropping {
    packet_sample_prob: f64,
    aggregate_to_occupancy: HashMap<String, usize>,
    aggregate_to_fair_rate: HashMap<String, usize>,
    aggregate_to_weight: HashMap<String, usize>,
    tree: FlowTree,
}

impl HierarchicalApproximateFairDropping {
    pub fn new (
        packet_sample_prob: f64,
        tree: FlowTree,
    ) -> Self {

        // TODO: Form the weight map from the tree.
        Self {
            packet_sample_prob,
            aggregate_to_occupancy: HashMap::new(),
            aggregate_to_fair_rate: HashMap::new(),
            aggregate_to_weight: HashMap::new(),
            tree,
        }
    }

    fn update_aggregate_stats(&mut self) {
        // TODO: Get the aggregate stats from the shadow buffer.
        // TODO: Update fair rates.
    }

    fn should_drop(&mut self, p: Pkt) -> bool {
        let aggregates = get_aggregates(p.clone());
        for aggregate in aggregates {
            drop_prob = 1.0 - self.aggregate_to_weight[aggregate] * self.aggregate_to_fair_rate[aggregate] / self.aggregate_to_occupancy[aggregate];
            if rand::random::<f64>() < drop_prob {
                return true;
            }
        }
    }
}

impl Scheduler for HierarchicalApproximateFairDropping {
    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        self.sample(p);

        if self.should_drop(p) {
            return Ok(());
        }

    }

    fn deq(&mut self) -> Result<Option<Pkt>, Report> {
        if self.inner.is_empty() {
            return Ok(None);
        }
        let p = self.inner.pop_front().unwrap();
        Some(p);
    }
}