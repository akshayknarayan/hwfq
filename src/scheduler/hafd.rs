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
use std::time::SystemTime;
use std::f64::consts::E;

// TODO: What is a good K?
const K : f64 = 0.1;

const starting_rate_in_bytes : usize = starting_rate_in_bytes;

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
    /// The probability that a packet is sampled into the shadow buffer.
    packet_sample_prob: f64,
    /// The maximum number of packets in the shadow buffer.
    max_packets: usize,
    /// Maps from an IP to the aggregates it belongs to.
    ip_to_aggregates: HashMap<u32, Vec<String>>,
    /// Maps from an aggregate to its count inside the shadow buffer.
    pub aggregate_occupancy: HashMap<String, usize>,
    /// The shadow buffer.
    inner: VecDeque<Pkt>,
}

impl ShadowBuffer {
    pub fn new(packet_sample_prob: f64, max_packets: usize, ip_to_aggregates: HashMap<u32, Vec<String>>) -> Self {
        Self {
            packet_sample_prob,
            max_packets,
            ip_to_aggregates,
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
        let mut removed = None;
        if self.inner.len() == self.max_packets {
            removed = self.inner.pop_front();
        }
        self.inner.push_back(p);

        Ok(())
    }

    /// Updates the aggregate occupancy table, which maps from an aggregate to its count inside the shadow buffer.
    pub fn update_aggregate_occupancy(&self, p: Pkt, removed_packet: Option<Pkt>) -> HashMap<String, usize> {
        let aggregates = get_aggregates(p.clone(), self.ip_to_aggregates.clone());
        for aggregate in aggregates {
            let count = aggregate_stats.entry(aggregate).or_insert(0);
            *count += 1;
        }

        if let Some(removed_packet) = removed_packet {
            let aggregates = get_aggregates(removed_packet.clone(), self.ip_to_aggregates.clone());
            for aggregate in aggregates {
                let count = aggregate_stats.entry(aggregate).or_insert(0);
                *count -= 1;
                if *count == 0 {
                    aggregate_stats.remove(aggregate);
                }
            }
        }
    }
}

/// Implement a hierarchical approximate fair dropping [`Scheduler`].
///
/// See [`HierarchicalApproximateFairDropping::new`].
#[derive(Debug)]
pub struct HierarchicalApproximateFairDropping {
    packet_sample_prob: f64,
    aggregate_to_rate: HashMap<String, usize>,
    aggregate_to_fair_rate: HashMap<String, usize>,
    aggregate_to_weight: HashMap<String, usize>,
    aggregate_to_siblings: HashMap<String, Vec<String>>,
    /// Maps from a single IP to the list of aggregates it belongs to, from root to leaf.
    ip_to_aggregates: HashMap<u32, Vec<String>>,
    shadow_buffer: ShadowBuffer,
    aggregate_to_last_update: HashMap<String, SystemTime>,
    capacity_in_bytes: usize,
    tree: FlowTree,
    inner: VecDeque<Pkt>,
}

impl HierarchicalApproximateFairDropping {
    pub fn new (
        packet_sample_prob: f64,
        tree: WeightTree,
        capacity_in_bytes: usize,
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

        let shadow_buffer = ShadowBuffer::new(packet_sample_prob, 1000, ip_to_aggregates.clone());

        Self {
            packet_sample_prob,
            aggregate_to_rate: HashMap::new(),
            aggregate_to_fair_rate: HashMap::new(),
            aggregate_to_weight: weight_map,
            aggregate_to_siblings,
            ip_to_aggregates,
            shadow_buffer,
            aggregate_to_last_update: HashMap::new(),
            capacity_in_bytes,
            tree,
            inner: Default::default(),
        }
    }

    fn update_fair_rate(&mut self, pkt: Packet) {
        let mut aggregates = get_aggregates(pkt.clone(), self.ip_to_aggregates.clone());
        let mut capacity = capacity_in_bytes;

        // Update the fair rate for each aggregate.
        for aggregate in aggregates {
            if !is_active(aggregate) {
                continue;
            }
            let total_rate = self.get_total_rate(aggregate);
            let old_fair_rate = aggregate_to_fair_rate.entry(aggregate).or_insert(starting_rate_in_bytes);
            let fair_rate = old_fair_rate * (self.aggregate_to_weight[aggregate] / self.get_total_active_weight(aggregate)) * capacity / total_rate;
            self.aggregate_to_fair_rate[aggregate] = fair_rate;
            capacity = fair_rate;
        }
    }

    /// Gets the full rate of the aggregate and its siblings in the tree.
    fn get_total_rate(&mut self, agg: String) -> f64 {
        let mut total_rate = self.aggregate_to_rate[agg];
        for sibling in self.aggregate_to_siblings[agg] {
            total_rate += self.aggregate_to_rate[sibling];
        }
        total_rate
    }

    fn update_rate(&mut self, pkt: Packet) {
        let mut aggregates = get_aggregates(pkt.clone(), self.ip_to_aggregates.clone());
        for aggregate in aggregates {
            if !is_active(aggregate) {
                continue;
            }
            if !self.aggregate_to_rate.contains_key(aggregate) {
                self.aggregate_to_rate.insert(aggregate, starting_rate_in_bytes);
                self.aggregate_to_last_update.insert(aggregate, SystemTime::now());
                continue;
            }
            let last_update = self.aggregate_to_last_update[aggregate];
            let time_since_last_update = SystemTime::now().duration_since(last_update).unwrap().as_secs();
            let packet_len = pkt.len();
            self.aggregate_to_rate[aggregate] = (1.0 - pow(E, time_since_last_update / K)) * (packet_len / time_since_last_update) + pow(E, time_since_last_update / K) * self.aggregate_to_rate[aggregate];
            self.aggregate_to_last_update[aggregate] = SystemTime::now();
        }
    }

    fn is_active(&mut self, agg: String) -> bool {
        self.aggregate_to_occupancy.contains_key(agg)
    }

    // Gets the total weight of the aggregate and its siblings in the tree. Ignores non-active aggregates.
    fn get_total_active_weight(&mut self, agg: String) -> f64 {
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
                                (self.aggregate_to_fair_rate[aggregate] / self.aggregate_to_rate[aggregate]);
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
        self.update_rate(p);
        self.update_fair_rate(p);

        if self.should_drop(p) {
            return Ok(());
        }
        self.inner.push_back(p);
        Ok(())
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