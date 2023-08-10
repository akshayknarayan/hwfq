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

// Hashes a vector of IPs to a string aggregate name.
fn ip_set_to_agg_name(ips: &Vec<u32>) -> String {
    let mut ips = ips.clone();
    ips.sort();
    ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(",")
}

fn get_aggregates(packet: Pkt, ip_to_aggregates: HashMap<u32, Vec<String>>) -> Vec<String> {
    let src_ip = packet.ip_hdr.src_ip;
    
    // Turn the source IP into a String joined with periods.
    let src_ip = format!(
        "{}.{}.{}.{}",
        src_ip[0], src_ip[1], src_ip[2], src_ip[3]
    );

    let mut aggregates = Vec::new();
    ip_to_aggregates.get(parse_ip(src_ip.as_str()).unwrap()).unwrap().clone()
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

/// Implement a hierarchical approximate fair dropping [`Scheduler`].
///
/// See [`HierarchicalApproximateFairDropping::new`].
#[derive(Debug)]
pub struct HierarchicalApproximateFairDropping {
    packet_sample_prob: f64,
    aggregate_to_occupancy: HashMap<String, usize>,
    aggregate_to_fair_rate: HashMap<String, usize>,
    aggregate_to_weight: HashMap<String, usize>,
    aggregate_to_siblings: HashMap<String, Vec<String>>,
    ip_to_aggregates: HashMap<u32, Vec<String>>,
    tree: FlowTree,
}

impl HierarchicalApproximateFairDropping {
    pub fn new (
        packet_sample_prob: f64,
        tree: WeightTree,
    ) -> Self {

        let mut aggregate_to_siblings = HashMap::new();
        let mut weight_map = HashMap::new();
        let mut ip_to_aggregates = HashMap::new();
        let mut weight_map = HashMap::new();

        // Form the weight map from the tree.
        fn weight_tree_helper(tree: WeightTree, weight_map: &mut HashMap<String, usize>) {
            match tree {
                WeightTree::Leaf { weight, ips} => {
                    let agg = ip_set_to_agg_name(&ips);
                    ip_to_aggregates.insert(ips[0], vec![]);
                    weight_map.insert(agg, weight);
                    aggregate_to_siblings.insert(agg, vec![]);
                }
                WeightTree::NonLeaf { weight, ips, children} => {
                    let agg = ip_set_to_agg_name(ips);
                    for ip in ips {
                        if !ip_to_aggregates.contains_key(ip) {
                            ip_to_aggregates.insert(ip, vec![]);
                        } 
                        ip_to_aggregates.get_mut(ip).unwrap().push(agg.clone());
                    }
                    let mut children_aggregates = vec![];
                    for child in children {
                        if let Some(child) = child {
                            weight_tree_helper(*child, weight_map);
                            children_aggregates.push(ip_set_to_agg_name(&child.ips));
                        }
                    }
                    for child_agg in children_aggregates {
                        let siblings = children_aggregates.clone();
                        siblings.remove(child_agg);
                        aggregate_to_siblings.insert(child_agg, siblings);
                    }
                }
            }
        }
        weight_tree_helper(tree, &mut weight_map);

        Self {
            packet_sample_prob,
            aggregate_to_occupancy: HashMap::new(),
            aggregate_to_fair_rate: HashMap::new(),
            aggregate_to_weight: weight_map,
            aggregate_to_siblings,
            ip_to_aggregates,
            tree,
        }
    }

    fn update_aggregate_stats(&mut self) {
        // Get new aggregate stats from the shadow buffer.
        self.aggregate_to_occupancy = self.shadow_buffer.get_aggregate_occupancy();

        // TODO: Update fair rates.
    }

    fn is_active(agg: String) -> bool {
        self.aggregate_to_occupancy.contains_key(agg)
    }

    // Gets the total weight of the aggregate and its siblings in the tree. Ignores non-active aggregates.
    fn get_total_active_weight(agg: String) -> f64 {
        let mut total_weight = self.aggregate_to_weight[agg];
        for sibling in self.aggregate_to_siblings[agg] {
            if is_active(sibling) {
                total_weight += self.aggregate_to_weight[sibling];
            }
        }
        total_weight
    }

    fn should_drop(&mut self, p: Pkt) -> bool {
        let aggregates = get_aggregates(p.clone());
        for aggregate in aggregates {
            if !self.aggregate_to_occupancy.contains_key(aggregate) ||
                !self.aggregate_to_fair_rate.contains_key(aggregate) || 
                !self.aggregate_to_weight.contains_key(aggregate) {
                continue;
            }
            drop_prob = 1.0 - (self.aggregate_to_weight[aggregate] / self.get_total_active_weight(aggregate)) *
                                (self.aggregate_to_fair_rate[aggregate] / self.aggregate_to_occupancy[aggregate]);
            if rand::random::<f64>() < drop_prob {
                return true;
            }
        }
        return false;
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
        Ok(Some(p));
    }

    fn dbg(&self) {
        debug!(?self.inner);
    }
}