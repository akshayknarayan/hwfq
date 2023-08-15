use super::Scheduler;
use crate::Pkt;
use color_eyre::eyre::Report;
use std::collections::HashMap;
use std::collections::VecDeque;
use tracing::debug;
use crate::scheduler::common::WeightTree;
use crate::scheduler::common::parse_ip;
use std::time::SystemTime;
use std::f64::consts::E;

// TODO: What is a good K?
const K : f64 = 0.0001;

const STARTING_RATE_IN_BYTES : f64 = 5000.0;

const MAX_PACKETS : usize = 1000;

// Hashes a vector of IPs to a string aggregate name.
fn ip_set_to_agg_name(ips: &[Vec<u32>]) -> String {
    let mut new_ips = ips.clone().to_vec();
    new_ips.sort();
    new_ips.iter().map(|ip| ip.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(".")).collect::<Vec<String>>().join("_")
}

fn get_aggregates(packet: &Pkt, ip_to_aggregates: &HashMap<u32, Vec<String>>) -> Vec<String> {
    let src_ip = packet.ip_hdr.source;
    
    // Turn the source IP into a String joined with periods.
    let new_src_ip = format!(
        "{}.{}.{}.{}",
        src_ip[0], src_ip[1], src_ip[2], src_ip[3]
    );

    debug!("New src ip: {}", new_src_ip);

    let parsed_ip = parse_ip(new_src_ip.as_str()).expect("Failed to parse IP");
    ip_to_aggregates.get(&parsed_ip).expect("Failed to get aggregates from IP").clone()
}
#[derive(Debug)]
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
            aggregate_occupancy: HashMap::new(),
            inner: Default::default(),
        }
    }

    pub fn sample(&mut self, p: &Pkt) -> Result<(), Report> {
        if rand::random::<f64>() < self.packet_sample_prob {
            self.enq(p.clone())?;
        }
        Ok(())
    }

    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        // If we are at capacity pop the oldest packet.
        let mut removed = None;
        if self.inner.len() == self.max_packets {
            removed = self.inner.pop_front();
        }
        self.update_aggregate_occupancy(&p, removed);
        self.inner.push_back(p);

        Ok(())
    }

    /// Updates the aggregate occupancy table, which maps from an aggregate to its count inside the shadow buffer.
    pub fn update_aggregate_occupancy(&mut self, p: &Pkt, removed_packet: Option<Pkt>) {
        let aggregates = get_aggregates(p, &self.ip_to_aggregates);
        for aggregate in aggregates {
            let count = self.aggregate_occupancy.entry(aggregate).or_insert(0);
            *count += 1;
        }

        if let Some(removed_packet) = removed_packet {
            let aggregates = get_aggregates(&removed_packet, &self.ip_to_aggregates);
            for aggregate in aggregates {
                let count = self.aggregate_occupancy.entry(aggregate.clone()).or_insert(0);
                *count -= 1;
                if *count == 0 {
                    self.aggregate_occupancy.remove(&aggregate);
                }
            }
        }
    }

    /// Gets the total number of packets in the shadow buffer.
    pub fn get_total_packets(&self) -> usize {
        self.inner.len()
    }

    fn dbg(&self) {
        debug!(?self.inner);
    }
}

/// Implement a hierarchical approximate fair dropping [`Scheduler`].
///
/// See [`HierarchicalApproximateFairDropping::new`].
#[derive(Debug)]
pub struct HierarchicalApproximateFairDropping {
    aggregate_to_rate: HashMap<String, f64>,
    aggregate_to_fair_rate: HashMap<String, f64>,
    aggregate_to_weight: HashMap<String, f64>,
    aggregate_to_siblings: HashMap<String, Vec<String>>,
    /// Maps from a single IP to the list of aggregates it belongs to, from root to leaf.
    ip_to_aggregates: HashMap<u32, Vec<String>>,
    shadow_buffer: ShadowBuffer,
    capacity_in_bytes: usize,
    ingress_rate : f64,
    last_time_update: SystemTime,
    inner: VecDeque<Pkt>,
}

impl HierarchicalApproximateFairDropping {
    pub fn new (
        packet_sample_prob: f64,
        tree: WeightTree,
        capacity_in_bytes: usize,
    ) -> Self {

        let mut aggregate_to_siblings = HashMap::new();
        let mut ip_to_aggregates : HashMap<u32, Vec<String>> = HashMap::new();
        let mut weight_map : HashMap<String, f64> = HashMap::new();

        // Form the weight map from the tree.
        fn weight_tree_helper(tree: WeightTree, weight_map: &mut HashMap<String, f64>,
                                ip_to_aggregates: &mut HashMap<u32, Vec<String>>, aggregate_to_siblings: &mut HashMap<String, Vec<String>>, set_ips: Option<Vec<u32>>) {
            match tree {
                WeightTree::Leaf { weight, ..} => {
                    let ips = set_ips.unwrap();
                    // Print out the ips.
                    debug!("IPS: {:?}", ips);
                    debug!("Weight: {}", weight);
                    let ip_array = [ips.clone()];
                    let agg = ip_set_to_agg_name(&ip_array);
                    let aggs = vec![agg.clone()];
                    ip_to_aggregates.insert(ips[0], aggs.clone());
                    weight_map.insert(agg.clone(), weight as f64);
                    aggregate_to_siblings.insert(agg, vec![]);
                }
                WeightTree::NonLeaf { weight, ips, children} => {
                    // Print out the ips.
                    debug!("IPS: {:?}", ips);
                    debug!("Weight: {}", weight);
                    let agg = ip_set_to_agg_name(&ips);
                    weight_map.insert(agg.clone(), weight as f64);
                    for ip_vec in ips.clone() {
                        for ip in ip_vec {
                            if !ip_to_aggregates.contains_key(&ip.clone()) {
                                ip_to_aggregates.insert(ip, vec![]);
                            } 
                            ip_to_aggregates.get_mut(&ip).unwrap().push(agg.clone());
                        }
                    }
                    let mut children_aggregates = vec![];
                    for i in 0..children.len() {
                        let child = children.get(i).unwrap();
                        let ips = ips[i].clone();
                        if let Some(child) = child {
                            weight_tree_helper(*child.clone(), weight_map, ip_to_aggregates, aggregate_to_siblings, Some(ips.clone()));
                            let new_child = child.clone();
                            match new_child.as_ref() {
                                WeightTree::Leaf { weight: _, ips} => {
                                    let ip_array = [ips.clone()];
                                    let agg = ip_set_to_agg_name(&ip_array);
                                    children_aggregates.push(agg);
                                }
                                WeightTree::NonLeaf { weight: _, ips, children: _} => {
                                    let agg = ip_set_to_agg_name(ips);
                                    children_aggregates.push(agg);
                                }
                            }
                        }
                    }
                    for child_agg in children_aggregates.clone() {
                        let siblings = children_aggregates.clone().into_iter().filter(|x| x != &child_agg).collect::<Vec<String>>();
                        aggregate_to_siblings.insert(child_agg, siblings);
                    }
                }
            }
        }
        weight_tree_helper(tree, &mut weight_map, &mut ip_to_aggregates, &mut aggregate_to_siblings, None);

        let shadow_buffer = ShadowBuffer::new(packet_sample_prob, MAX_PACKETS, ip_to_aggregates.clone());

        debug!("Capacity in bytes: {}", capacity_in_bytes);

        Self {
            aggregate_to_rate: HashMap::new(),
            aggregate_to_fair_rate: HashMap::new(),
            aggregate_to_weight: weight_map,
            aggregate_to_siblings,
            ip_to_aggregates,
            shadow_buffer,
            capacity_in_bytes,
            ingress_rate: 0.0,
            last_time_update: SystemTime::now(),
            inner: Default::default(),
        }
    }

    fn update_ingress_rate(&mut self, pkt: &Pkt) {
        let time_since_last_update = SystemTime::now().duration_since(self.last_time_update).unwrap().as_secs_f64();
        let packet_len = pkt.len() as f64;
        self.ingress_rate = (1.0 - f64::powf(E, -time_since_last_update / K)) * (packet_len / time_since_last_update) + f64::powf(E, -time_since_last_update / K) * self.ingress_rate;
        self.last_time_update = SystemTime::now();
    }

    fn update_fair_rate(&mut self, pkt: &Pkt) {
        debug!("Updating fair rate");
        let aggregates = get_aggregates(pkt, &self.ip_to_aggregates);
        let mut capacity = self.capacity_in_bytes as f64;

        // Update the fair rate for each aggregate.
        for aggregate in aggregates {
            if !self.is_active(&aggregate) || !self.aggregate_to_rate.contains_key(&aggregate) {
                continue;
            }
            if !self.aggregate_to_fair_rate.contains_key(&aggregate) {
                self.aggregate_to_fair_rate.insert(aggregate.clone(), STARTING_RATE_IN_BYTES);
            }
            let total_rate = self.get_total_rate(&aggregate);
            let old_fair_rate = self.aggregate_to_fair_rate.get(&aggregate).expect(format!("Failed to get fair rate for aggregate: {}", aggregate).as_str()).clone();
            let fair_rate = old_fair_rate * (self.aggregate_to_weight.get(&aggregate).expect(format!("Failed to get weight for aggregate: {}", aggregate).as_str()).clone() / self.get_total_active_weight(&aggregate)) * capacity / total_rate;
            self.aggregate_to_fair_rate.insert(aggregate.clone(), fair_rate);
            debug!("Aggregate: {} new fair rate: {}", aggregate, fair_rate);
            capacity = fair_rate;
        }
    }

    /// Gets the full rate of the aggregate and its siblings in the tree.
    fn get_total_rate(&mut self, agg: &String) -> f64 {
        let mut total_rate = self.aggregate_to_rate.get(agg).expect(format!("Failed to get rate for aggregate: {}", agg).as_str()).clone();
        let siblings = self.aggregate_to_siblings.get(agg).expect(format!("Failed to get siblings for aggregate: {}", agg).as_str()).clone();
        for sibling in siblings {
            total_rate += self.aggregate_to_rate.get(&sibling).expect(format!("Failed to get rate for sibling aggregate: {}", sibling).as_str()).clone();
        }
        total_rate
    }

    fn update_rate(&mut self, pkt: &Pkt) {
        let aggregates = get_aggregates(&pkt, &self.ip_to_aggregates);
        for aggregate in aggregates {
            if !self.is_active(&aggregate) {
                continue;
            }
            let occupancy = self.shadow_buffer.aggregate_occupancy.get(&aggregate).expect(format!("Failed to get aggregate occupancy for aggregate: {}", aggregate).as_str()).clone() as f64;
            let new_rate = occupancy / self.shadow_buffer.get_total_packets() as f64 * self.ingress_rate;
            self.aggregate_to_rate.insert(aggregate.clone(), new_rate);
        }
    }

    fn is_active(&mut self, agg: &String) -> bool {
        self.shadow_buffer.aggregate_occupancy.contains_key(agg)
    }

    // Gets the total weight of the aggregate and its siblings in the tree. Ignores non-active aggregates.
    fn get_total_active_weight(&mut self, agg: &String) -> f64 {
        let mut total_weight : f64 = self.aggregate_to_weight.get(agg).expect(format!("Failed to get weight for aggregate: {}", agg).as_str()).clone() as f64;
        for sibling in self.aggregate_to_siblings.get(agg).expect(format!("Failed to get siblings for aggregate: {}", agg).as_str()).clone() {
            if self.is_active(&sibling) {
                total_weight += self.aggregate_to_weight.get(&sibling).expect(format!("Failed to get weight for sibling aggregate: {}", sibling).as_str());
            }
        }
        total_weight
    }

    fn should_drop(&mut self, p: &Pkt) -> bool {
        let aggregates = get_aggregates(&p, &self.ip_to_aggregates);
        for aggregate in aggregates {
            if !self.is_active(&aggregate) ||
                !self.shadow_buffer.aggregate_occupancy.contains_key(&aggregate) ||
                !self.aggregate_to_fair_rate.contains_key(&aggregate) || 
                !self.aggregate_to_rate.contains_key(&aggregate) ||
                !self.aggregate_to_weight.contains_key(&aggregate) {
                continue;
            }
            let fair_rate = self.aggregate_to_fair_rate.get(&aggregate).expect(format!("Failed to get fair rate for aggregate: {}", aggregate).as_str()).clone();
            let rate = self.aggregate_to_rate.get(&aggregate).expect(format!("Failed to get rate for aggregate: {}", aggregate).as_str()).clone();
            let drop_prob = 1.0 - 
                                (fair_rate / rate);
            if rand::random::<f64>() < drop_prob {
                return true;
            }
        }
        return false;
    }
}

impl Scheduler for HierarchicalApproximateFairDropping {
    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        let res = self.shadow_buffer.sample(&p);
        if let Err(e) = res {
            return Err(e);
        }
        self.update_ingress_rate(&p);
        self.update_rate(&p);
        self.update_fair_rate(&p);

        if self.should_drop(&p) {
            debug!("Dropping packet: {:?}", p);
            return Ok(());
        }
        self.inner.push_back(p.clone());
        Ok(())
    }

    fn deq(&mut self) -> Result<Option<Pkt>, Report> {
        if self.inner.is_empty() {
            return Ok(None);
        }
        let p = self.inner.pop_front().unwrap();
        Ok(Some(p))
    }

    fn dbg(&self) {
        debug!(?self.inner);
    }
}