use super::Scheduler;
use crate::scheduler::common::parse_ip;
use crate::scheduler::common::WeightTree;
use crate::Pkt;
use color_eyre::eyre::Report;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::f64::consts::E;
use std::time::SystemTime;
use tracing::debug;

// TODO: What is a good K?
const K: f64 = 0.1;

const STARTING_RATE_IN_BYTES: f64 = 5000.0;

const MAX_PACKETS: usize = 1000;

// Hashes a vector of IPs to a string aggregate name.
fn ip_set_to_agg_name(ips: &[Vec<u32>]) -> String {
    let mut new_ips = ips.clone().to_vec();
    new_ips.sort();
    new_ips
        .iter()
        .map(|ip| {
            ip.iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join(".")
        })
        .collect::<Vec<String>>()
        .join("_")
}

fn exponential_smooth(old_value: f64, new_value: f64, time_since: f64, k: f64) -> f64 {
    (1.0 - f64::powf(E, -time_since / k)) * new_value + f64::powf(E, -time_since / k) * old_value
}

fn get_aggregates(packet: &Pkt, ip_to_aggregates: &HashMap<u32, Vec<String>>) -> Vec<String> {
    let src_ip = packet.ip_hdr.source;

    // Turn the source IP into a String joined with periods.
    let new_src_ip = format!("{}.{}.{}.{}", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);

    debug!("New src ip: {}", new_src_ip);

    let parsed_ip = parse_ip(new_src_ip.as_str()).expect("Failed to parse IP");
    ip_to_aggregates
        .get(&parsed_ip)
        .expect("Failed to get aggregates from IP")
        .clone()
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
    pub fn new(
        packet_sample_prob: f64,
        max_packets: usize,
        ip_to_aggregates: HashMap<u32, Vec<String>>,
    ) -> Self {
        Self {
            packet_sample_prob,
            max_packets,
            ip_to_aggregates,
            aggregate_occupancy: HashMap::new(),
            inner: Default::default(),
        }
    }

    pub fn sample(&mut self, p: &Pkt) -> Result<(), Report> {
        // if rand::random::<f64>() < self.packet_sample_prob {
        //     self.enq(p.clone())?;
        // }
        self.enq(p.clone())?;
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
                let count = self
                    .aggregate_occupancy
                    .entry(aggregate.clone())
                    .or_insert(0);
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
    ingress_rate: f64,
    last_time_update: SystemTime,
    inner: VecDeque<Pkt>,
}

impl HierarchicalApproximateFairDropping {
    pub fn new(packet_sample_prob: f64, tree: WeightTree, capacity_in_bytes: usize) -> Self {
        let mut aggregate_to_siblings = HashMap::new();
        let mut ip_to_aggregates: HashMap<u32, Vec<String>> = HashMap::new();
        let mut weight_map: HashMap<String, f64> = HashMap::new();

        // Form the weight map from the tree.
        fn weight_tree_helper(
            tree: WeightTree,
            weight_map: &mut HashMap<String, f64>,
            ip_to_aggregates: &mut HashMap<u32, Vec<String>>,
            aggregate_to_siblings: &mut HashMap<String, Vec<String>>,
            set_ips: Option<Vec<u32>>,
            aggregates: &[String],
        ) {
            match tree {
                WeightTree::Leaf { weight, .. } => {
                    let ips = set_ips.unwrap();
                    // Print out the ips.
                    debug!("IPS: {:?}", ips);
                    debug!("Weight: {}", weight);
                    let ip_array = [ips.clone()];
                    let agg = ip_set_to_agg_name(&ip_array);
                    let mut all_aggs = aggregates.to_vec();
                    all_aggs.push(agg.clone());
                    weight_map.insert(agg.clone(), weight as f64);
                    ip_to_aggregates.insert(ips[0], all_aggs.clone());
                    // aggregate_to_siblings.insert(agg, vec![]);
                }
                WeightTree::NonLeaf {
                    weight,
                    ips,
                    children,
                } => {
                    // Print out the ips.
                    debug!("IPS: {:?}", ips);
                    debug!("Weight: {}", weight);
                    let agg = ip_set_to_agg_name(&ips);
                    if !aggregate_to_siblings.contains_key(&agg) {
                        aggregate_to_siblings.insert(agg.clone(), vec![]);
                    }
                    weight_map.insert(agg.clone(), weight as f64);
                    let mut children_aggregates = vec![];
                    for (child, child_ips) in children.iter().zip(ips.iter()) {
                        let mut all_aggs = aggregates.to_vec();
                        all_aggs.push(agg.clone());
                        if let Some(child) = child {
                            weight_tree_helper(
                                *child.clone(),
                                weight_map,
                                ip_to_aggregates,
                                aggregate_to_siblings,
                                Some(child_ips.clone()),
                                &all_aggs,
                            );
                            let new_child = child.clone();
                            debug!("Matching child");
                            match new_child.as_ref() {
                                WeightTree::Leaf { weight: _, ips: _ } => {
                                    debug!("Matched as leaf");
                                    let ip_array = [child_ips.clone()];
                                    let agg = ip_set_to_agg_name(&ip_array);
                                    children_aggregates.push(agg);
                                }
                                WeightTree::NonLeaf {
                                    weight: _,
                                    ips: _,
                                    children: _,
                                } => {
                                    debug!("Matched as non leaf");
                                    let ip_array = [child_ips.clone()];
                                    let agg = ip_set_to_agg_name(&ip_array);
                                    children_aggregates.push(agg);
                                }
                            }
                        }
                    }
                    debug!("Child aggregates: {:?}", children_aggregates);
                    for child_agg in children_aggregates.clone() {
                        let siblings = children_aggregates
                            .clone()
                            .into_iter()
                            .filter(|x| x != &child_agg)
                            .collect::<Vec<String>>();
                        aggregate_to_siblings.insert(child_agg, siblings);
                    }
                }
            }
        }
        // let mut aggregates = vec!["root".to_string()];
        // aggregate_to_siblings.insert("root".to_string(), vec![]);
        // weight_map.insert("root".to_string(), 1.0);
        let aggregates = vec![];
        weight_tree_helper(
            tree,
            &mut weight_map,
            &mut ip_to_aggregates,
            &mut aggregate_to_siblings,
            None,
            &aggregates,
        );

        debug!("Weight map");
        for (k, v) in weight_map.clone() {
            debug!("  {}: {}", k, v);
        }
        debug!("IP to aggregates");
        for (k, v) in ip_to_aggregates.clone() {
            debug!("  {}: {:?}", k, v);
        }
        debug!("Aggregate to siblings");
        for (k, v) in aggregate_to_siblings.clone() {
            debug!("  {}: {:?}", k, v);
        }

        let shadow_buffer =
            ShadowBuffer::new(packet_sample_prob, MAX_PACKETS, ip_to_aggregates.clone());

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
        let time_since_last_update = SystemTime::now()
            .duration_since(self.last_time_update)
            .unwrap()
            .as_secs_f64();
        let packet_len = pkt.len() as f64;
        self.ingress_rate = exponential_smooth(
            self.ingress_rate,
            packet_len / time_since_last_update,
            time_since_last_update,
            K,
        );
        self.last_time_update = SystemTime::now();
    }

    fn update_fair_rate(&mut self, pkt: &Pkt) {
        debug!("Updating fair rate");
        let aggregates = get_aggregates(pkt, &self.ip_to_aggregates);
        let mut capacity = self.capacity_in_bytes as f64;

        // Update the fair rate for each aggregate.
        for aggregate in aggregates {
            debug!("  Aggregate: {}", aggregate);
            if !self.is_active(&aggregate) || !self.aggregate_to_rate.contains_key(&aggregate) {
                continue;
            }
            if !self.aggregate_to_fair_rate.contains_key(&aggregate) {
                self.aggregate_to_fair_rate
                    .insert(aggregate.clone(), capacity);
            }
            let total_rate = self.get_total_rate(&aggregate);
            let old_fair_rate = *self
                .aggregate_to_fair_rate
                .get(&aggregate)
                .unwrap_or_else(|| panic!("Failed to get fair rate for aggregate: {}", aggregate));
            debug!("    Full Ingress rate: {}", self.ingress_rate);
            debug!("    total rate: {}", total_rate);
            debug!("    old fair rate: {}", old_fair_rate);
            debug!("    Capacity: {}", capacity);
            debug!(
                "    Total weight: {}",
                self.get_total_active_weight(&aggregate)
            );
            debug!(
                "    Weight: {:?}",
                self.aggregate_to_weight.get(&aggregate).clone()
            );
            let fair_rate = old_fair_rate
                * (*self.aggregate_to_weight.get(&aggregate).unwrap_or_else(|| {
                    panic!("Failed to get weight for aggregate: {}", aggregate)
                }) / self.get_total_active_weight(&aggregate))
                * capacity
                / total_rate;
            // Value clamping code.
            // let mut num_siblings = self.aggregate_to_siblings.get(&aggregate).expect(format!("Failed to get siblings for aggregate: {}", aggregate).as_str()).len() as f64;
            // if num_siblings < 1.0 {
            //     num_siblings = 1.0;
            // }
            // if fair_rate > 10.0 * num_siblings * capacity {
            //     fair_rate = 10.0 * num_siblings * capacity;
            // }
            // if fair_rate < capacity / (10.0 * num_siblings) {
            //     fair_rate = capacity / (10.0 * num_siblings);
            // }
            self.aggregate_to_fair_rate
                .insert(aggregate.clone(), fair_rate);
            debug!("    New fair rate: {}", fair_rate);
            capacity = fair_rate;
        }
    }

    /// Gets the full rate of the aggregate and its descendents in the tree.
    fn get_total_rate(&mut self, agg: &String) -> f64 {
        let occupancy = *self
            .shadow_buffer
            .aggregate_occupancy
            .get(agg)
            .unwrap_or_else(|| panic!("Failed to get aggregate occupancy for aggregate: {}", agg))
            as f64;
        occupancy / self.shadow_buffer.get_total_packets() as f64 * self.ingress_rate
    }

    fn update_rate(&mut self, pkt: &Pkt) {
        let aggregates = get_aggregates(pkt, &self.ip_to_aggregates);
        debug!("Updating rate");
        for aggregate in aggregates {
            debug!("  Aggregate: {}", aggregate);
            if !self.is_active(&aggregate) {
                continue;
            }
            let occupancy = *self
                .shadow_buffer
                .aggregate_occupancy
                .get(&aggregate)
                .unwrap_or_else(|| {
                    panic!(
                        "Failed to get aggregate occupancy for aggregate: {}",
                        aggregate
                    )
                }) as f64;
            debug!("    Occupancy: {}", occupancy);
            debug!(
                "    Total packets: {}",
                self.shadow_buffer.get_total_packets()
            );
            debug!("    Ingress rate: {}", self.ingress_rate);
            let new_rate =
                occupancy / self.shadow_buffer.get_total_packets() as f64 * self.ingress_rate;
            debug!("    New rate: {}", new_rate);
            self.aggregate_to_rate.insert(aggregate.clone(), new_rate);
        }
    }

    fn is_active(&mut self, agg: &String) -> bool {
        self.shadow_buffer.aggregate_occupancy.contains_key(agg)
    }

    // Gets the total weight of the aggregate and its siblings in the tree. Ignores non-active aggregates.
    fn get_total_active_weight(&mut self, agg: &String) -> f64 {
        let mut total_weight = *self
            .aggregate_to_weight
            .get(agg)
            .unwrap_or_else(|| panic!("Failed to get weight for aggregate: {}", agg));
        for sibling in self
            .aggregate_to_siblings
            .get(agg)
            .unwrap_or_else(|| panic!("Failed to get siblings for aggregate: {}", agg))
            .clone()
        {
            if self.is_active(&sibling) {
                total_weight += self.aggregate_to_weight.get(&sibling).unwrap_or_else(|| {
                    panic!("Failed to get weight for sibling aggregate: {}", sibling)
                });
            }
        }
        total_weight
    }

    fn should_drop(&mut self, p: &Pkt) -> bool {
        let aggregates = get_aggregates(p, &self.ip_to_aggregates);
        for aggregate in aggregates {
            if !self.is_active(&aggregate)
                || !self
                    .shadow_buffer
                    .aggregate_occupancy
                    .contains_key(&aggregate)
                || !self.aggregate_to_fair_rate.contains_key(&aggregate)
                || !self.aggregate_to_rate.contains_key(&aggregate)
                || !self.aggregate_to_weight.contains_key(&aggregate)
            {
                continue;
            }
            let fair_rate = *self
                .aggregate_to_fair_rate
                .get(&aggregate)
                .unwrap_or_else(|| panic!("Failed to get fair rate for aggregate: {}", aggregate));
            let rate = *self
                .aggregate_to_rate
                .get(&aggregate)
                .unwrap_or_else(|| panic!("Failed to get rate for aggregate: {}", aggregate));
            let drop_prob = 1.0 - (fair_rate / rate);
            debug!("Aggregate: {} drop prob: {}", aggregate, drop_prob);
            if rand::random::<f64>() < drop_prob {
                return true;
            }
        }

        false
    }
}

impl Scheduler for HierarchicalApproximateFairDropping {
    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        self.shadow_buffer.sample(&p)?;
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

#[cfg(test)]
mod t {
    use crate::{scheduler::common::WeightTree, Pkt, Scheduler};

    fn init() {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            tracing_subscriber::fmt::init();
            color_eyre::install().unwrap();
        })
    }

    fn make_test_tree() -> (
        super::HierarchicalApproximateFairDropping,
        [u8; 4],
        [u8; 4],
        [u8; 4],
    ) {
        let all_ips = [
            u32::from_be_bytes([42, 0, 0, 0]),
            u32::from_be_bytes([42, 1, 1, 1]),
            u32::from_be_bytes([42, 1, 2, 1]),
        ];
        let wt = WeightTree::parent(1)
            .add_child(vec![all_ips[0]], WeightTree::leaf(1)) // "B"
            .unwrap()
            .add_child(
                all_ips[1..].to_vec(),
                WeightTree::parent(2)
                    .add_child(vec![all_ips[1]], WeightTree::leaf(1)) // "D"
                    .unwrap()
                    .add_child(vec![all_ips[2]], WeightTree::leaf(2)) // "E"
                    .unwrap(),
            )
            .unwrap();

        dbg!(wt.get_min_quantum().unwrap());
        let hwfq = super::HierarchicalApproximateFairDropping::new(
            0.1, wt, 150_000, /* 100 x 1500 bytes */
        );

        (
            hwfq,
            u32::to_be_bytes(all_ips[0]),
            u32::to_be_bytes(all_ips[1]),
            u32::to_be_bytes(all_ips[2]),
        )
    }

    #[test]
    fn hwfq_basic() {
        init();
        let (mut hwfq, b_ip, d_ip, e_ip) = make_test_tree();
        let dst_ip = [42, 2, 0, 0];

        // enqueue a bunch of packets
        for _ in 0..100 {
            hwfq.enq(Pkt {
                ip_hdr: etherparse::Ipv4Header::new(
                    100,
                    64,
                    etherparse::IpNumber::Tcp,
                    b_ip,
                    dst_ip,
                ),
                buf: vec![0u8; 100],
            })
            .unwrap();
            hwfq.enq(Pkt {
                ip_hdr: etherparse::Ipv4Header::new(
                    100,
                    64,
                    etherparse::IpNumber::Tcp,
                    d_ip,
                    dst_ip,
                ),
                buf: vec![0u8; 100],
            })
            .unwrap();
            hwfq.enq(Pkt {
                ip_hdr: etherparse::Ipv4Header::new(
                    100,
                    64,
                    etherparse::IpNumber::Tcp,
                    e_ip,
                    dst_ip,
                ),
                buf: vec![0u8; 100],
            })
            .unwrap();
        }

        let mut b_cnt = 0;
        let mut d_cnt = 0;
        let mut e_cnt = 0;
        for _ in 0..180 {
            let p = hwfq.deq().unwrap().unwrap();
            if p.ip_hdr.source == b_ip {
                b_cnt += 1;
            } else if p.ip_hdr.source == d_ip {
                d_cnt += 1;
            } else if p.ip_hdr.source == e_ip {
                e_cnt += 1;
            } else {
                panic!("unknown ip");
            }
        }

        // should be d + e ~= 2 * b, e ~= 2 * d
        dbg!(b_cnt, d_cnt, e_cnt);
        let sum_d_e = (d_cnt + e_cnt) as isize;
        let twice_b = (b_cnt * 2) as isize;
        assert!((sum_d_e - twice_b).abs() < 5);
        let e = e_cnt as isize;
        let twice_d = (d_cnt * 2) as isize;
        assert!((twice_d - e).abs() < 5);
    }
}
