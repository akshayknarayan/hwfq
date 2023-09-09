use super::Scheduler;
use crate::scheduler::common::parse_ip;
use crate::scheduler::common::WeightTree;
use crate::Pkt;
use color_eyre::eyre::Report;
use rand::RngCore;
use rand::SeedableRng;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::f64::consts::E;
use std::time::SystemTime;
use tracing::debug;
use tracing::info;
use rand::rngs::StdRng;

const MAX_PACKETS : usize = 1000;

const ALPHA: f64 = 1.7;
const BETA: f64 = 1.8;
const K: f64 = 0.1;

const UPDATE_FREQUENCY: f64 = 160.0;

const TARGET_QUEUE_LENGTH: f64 = 50.0;

const MIN_M_FAIR: f64 = 10.0;
const MAX_M_FAIR: f64 = MAX_PACKETS as f64 * 100.0;

fn exponential_smooth(old_value: f64, new_value: f64, time_since: f64, k: f64) -> f64 {
    // (1.0 - f64::powf(E, -time_since / k)) * new_value + f64::powf(E, -time_since / k) * old_value
    (old_value + new_value) / 2.0
}

fn get_ip(packet: &Pkt, lookup_on_src_ip: bool) -> [u8; 4] {
    if lookup_on_src_ip {
        packet.ip_hdr.source
    } else {
        packet.ip_hdr.destination
    }
}

// Hashes a vector of IPs to a string aggregate name.
fn ip_set_to_agg_name(ips: &[Vec<u32>]) -> String {
    let mut new_ips = ips.clone().to_vec();
    info!("New ips: {:?}", new_ips);
    // Remove all 0 length IPs.
    new_ips.retain(|x| x.len() > 0);
    // Flatten the vector of IPs into a single vector.
    let mut flat_ips = vec![];
    for ip in new_ips {
        for ip_part in ip {
            flat_ips.push(ip_part);
        }
    }
    flat_ips.sort();
    flat_ips
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join("_")

}

fn get_aggregates(packet: &Pkt, ip_to_aggregates: &HashMap<u32, Vec<String>>, lookup_on_src_ip: bool) -> Vec<String> {
    let src_ip = get_ip(packet, lookup_on_src_ip);

    // Turn the source IP into a String joined with periods.
    let new_src_ip = format!("{}.{}.{}.{}", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);

    // debug!("New src ip: {}", new_src_ip);

    let parsed_ip = parse_ip(new_src_ip.as_str()).expect("Failed to parse IP");
    ip_to_aggregates
        .get(&parsed_ip)
        .expect(&format!("Failed to get aggregates from IP: {}", parsed_ip))
        .clone()
}

#[derive(Debug)]
pub struct ShadowBuffer {
    /// The probability that a packet is sampled into the shadow buffer.
    packet_sample_prob: f64,
    /// The maximum number of packets in the shadow buffer.
    pub max_packets: usize,
    /// Maps from an IP to the aggregates it belongs to.
    ip_to_aggregates: HashMap<u32, Vec<String>>,
    /// Maps from an aggregate to its count inside the shadow buffer.
    aggregate_occupancy: HashMap<String, usize>,
    // Aggregate to weight map.
    aggregate_to_weight: HashMap<String, f64>,
    // Aggregate to weight map.
    aggregate_to_weight_share: HashMap<String, f64>,
    // Aggregate to siblings map.
    aggregate_to_siblings: HashMap<String, Vec<String>>,
    /// The time of the last update to m_fair.
    last_update_time: SystemTime,
    m_fair: f64,
    /// The random number generator.
    rng: StdRng,
    lookup_on_src_ip: bool,
    /// The shadow buffer.
    inner: VecDeque<Pkt>,
}

impl ShadowBuffer {
    pub fn new(packet_sample_prob: f64, max_packets: usize, ip_to_aggregates: &HashMap<u32, Vec<String>>,
        aggregate_to_weight: HashMap<String, f64>, aggregate_to_siblings: HashMap<String, Vec<String>>,
        lookup_on_src_ip: bool) -> Self {
        Self {
            packet_sample_prob,
            max_packets,
            ip_to_aggregates: ip_to_aggregates.clone(),
            aggregate_occupancy: HashMap::new(),
            aggregate_to_weight,
            aggregate_to_siblings,
            aggregate_to_weight_share: HashMap::new(),
            last_update_time: SystemTime::now(),
            m_fair: MIN_M_FAIR,
            rng: StdRng::seed_from_u64(0),
            lookup_on_src_ip,
            inner: Default::default(),
        }
    }

    pub fn sample(&mut self, p: &Pkt) -> Result<(), Report> {
        self.update_weight_shares(&p);
        if self.get_rand_f64() < self.packet_sample_prob {
            self.enq(p.clone())?;
        }
        Ok(())
    }

    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        // If we are at capacity pop the oldest packet.
        let mut removed = None;
        if self.inner.len() >= self.max_packets {
            removed = self.inner.pop_front();
        }
        self.update_aggregate_occupancy(&p, removed);
        self.update_weight_shares(&p);
        self.inner.push_back(p);

        Ok(())
    }

    /// Gets the total number of packets in the shadow buffer.
    pub fn size(&self) -> usize {
        self.inner.len()
    }

    fn dbg(&self) {
        debug!(?self.inner);
    }

    /// Updates the aggregate occupancy table, which maps from an aggregate to its count inside the shadow buffer.
    pub fn update_aggregate_occupancy(&mut self, p: &Pkt, removed_packet: Option<Pkt>) {
        let aggregates = get_aggregates(p, &self.ip_to_aggregates, self.lookup_on_src_ip);
        for aggregate in aggregates {
            // Increment the count for the aggregate.
            if !self.aggregate_occupancy.contains_key(&aggregate) {
                self.aggregate_occupancy.insert(aggregate.clone(), 0);
            }
            self.aggregate_occupancy.insert(aggregate.clone(), self.aggregate_occupancy.get(&aggregate).unwrap_or_else(|| panic!("Failed to get aggregate occupancy for aggregate: {}", aggregate)).clone() + 1);
        }

        if let Some(removed_packet) = removed_packet {
            let aggregates = get_aggregates(&removed_packet, &self.ip_to_aggregates, self.lookup_on_src_ip);
            for aggregate in aggregates {
                self.aggregate_occupancy.insert(aggregate.clone(), self.aggregate_occupancy.get(&aggregate).unwrap_or_else(|| panic!("Failed to get aggregate occupancy for aggregate: {}", aggregate)).clone() - 1);
                if self.aggregate_occupancy.get(&aggregate).unwrap_or_else(|| panic!("Failed to get aggregate occupancy for aggregate: {}", aggregate)).clone() == 0 {
                    self.aggregate_occupancy.remove(&aggregate);
                }
            }
        }
    }

    fn clamp_m_fair(&mut self) {
        if self.m_fair < MIN_M_FAIR {
            self.m_fair = MIN_M_FAIR;
        } else if self.m_fair > MAX_M_FAIR {
            self.m_fair = MAX_M_FAIR;
        }
    }

    pub fn update_mfair(&mut self, queue_length : usize, last_queue_length : usize) {
        self.m_fair = self.m_fair + ALPHA * (last_queue_length as f64 - TARGET_QUEUE_LENGTH) - BETA * (queue_length as f64 - TARGET_QUEUE_LENGTH);
        self.clamp_m_fair();
    }

    pub fn should_update_mfair(&self) -> bool {
        let time_since_last_m_fair_update = self.last_update_time.elapsed().unwrap().as_secs_f64();
        time_since_last_m_fair_update > 1.0 / UPDATE_FREQUENCY
    }

    // Gets the total weight and inactive occupancy of the aggregate and its siblings in the tree. Ignores non-active aggregates.
    fn get_total_weight(&mut self, agg: &String) -> f64 {
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
            total_weight += self.aggregate_to_weight.get(&sibling).unwrap_or_else(|| {
                panic!("Failed to get weight for sibling aggregate: {}", sibling)
            });
        }
        total_weight
    }

    pub fn update_weight_shares(&mut self, p: &Pkt) {
        let aggregates = get_aggregates(&p, &self.ip_to_aggregates, self.lookup_on_src_ip);
        let mut current_weight = 1.0;
        for aggregate in aggregates {
            let total_weight = self.get_total_weight(&aggregate);
            let weight_share = current_weight * self.aggregate_to_weight.get(&aggregate).unwrap_or_else(|| panic!("Failed to get weight for aggregate: {}", aggregate)) / total_weight;
            current_weight = weight_share;
            self.aggregate_to_weight_share.insert(aggregate.clone(), weight_share);
        }
    }

    pub fn occupancy(&self, aggregate: &String) -> usize {
        self.aggregate_occupancy.get(aggregate).unwrap_or_else(|| panic!("Failed to get aggregate occupancy for aggregate: {}", aggregate)).clone()
    }

    pub fn weight_share(&self, aggregate: &String) -> f64 {
        self.aggregate_to_weight_share.get(aggregate).unwrap_or_else(|| panic!("Failed to get weight share for aggregate: {}", aggregate)).clone()
    }

    pub fn get_rand_f64(&mut self) -> f64 {
        self.rng.next_u64() as f64 / u64::MAX as f64
    }

    pub fn is_constrained(&mut self, agg: &String) -> bool {
        self.aggregate_occupancy.contains_key(agg) && (self.occupancy(agg) > 10)
    }
}

/// Implement a hierarchical approximate fair dropping [`Scheduler`].
///
/// See [`HierarchicalApproximateFairDropping::new`].
#[derive(Debug)]
pub struct HierarchicalApproximateFairDropping {
    /// Maps from a single IP to the list of aggregates it belongs to, from root to leaf.
    ip_to_aggregates: HashMap<u32, Vec<String>>,
    shadow_buffer: ShadowBuffer,
    lookup_on_src_ip: bool,
    aggregate_to_update_and_ingress_rate: HashMap<String, (SystemTime, f64)>,
    aggregate_to_update_and_egress_rate: HashMap<String, (SystemTime, f64)>,
    last_egress_update: SystemTime,
    last_ingress_update: SystemTime,
    last_queue_length: usize,
    inner: VecDeque<Pkt>,
}

impl HierarchicalApproximateFairDropping {
    pub fn new(packet_sample_prob: f64, tree: WeightTree, lookup_on_src_ip: bool) -> Self {
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
                    // debug!("IPS: {:?}", ips);
                    // debug!("Weight: {}", weight);
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
                    // debug!("IPS: {:?}", ips);
                    // debug!("Weight: {}", weight);
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
                            // debug!("Matching child");
                            match new_child.as_ref() {
                                WeightTree::Leaf { weight: _, ips: _ } => {
                                    // debug!("Matched as leaf");
                                    let ip_array = [child_ips.clone()];
                                    let agg = ip_set_to_agg_name(&ip_array);
                                    children_aggregates.push(agg);
                                }
                                WeightTree::NonLeaf {
                                    weight: _,
                                    ips: _,
                                    children: _,
                                } => {
                                    // debug!("Matched as non leaf");
                                    let ip_array = [child_ips.clone()];
                                    let agg = ip_set_to_agg_name(&ip_array);
                                    children_aggregates.push(agg);
                                }
                            }
                        }
                    }
                    // debug!("Child aggregates: {:?}", children_aggregates);
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
        let aggregates = vec![];
        weight_tree_helper(
            tree,
            &mut weight_map,
            &mut ip_to_aggregates,
            &mut aggregate_to_siblings,
            None,
            &aggregates,
        );

        info!("Weight map");
        for (k, v) in weight_map.clone() {
            info!("  {}: {}", k, v);
        }
        info!("IP to aggregates");
        for (k, v) in ip_to_aggregates.clone() {
            info!("  {}: {:?}", k, v);
        }
        info!("Aggregate to siblings");
        for (k, v) in aggregate_to_siblings.clone() {
            info!("  {}: {:?}", k, v);
        }

        let shadow_buffer =
            ShadowBuffer::new(packet_sample_prob, MAX_PACKETS, &ip_to_aggregates, weight_map.clone(), aggregate_to_siblings.clone(), lookup_on_src_ip);

        Self {
            ip_to_aggregates,
            shadow_buffer,
            lookup_on_src_ip,
            aggregate_to_update_and_ingress_rate: HashMap::new(),
            aggregate_to_update_and_egress_rate: HashMap::new(),
            last_egress_update: SystemTime::now(),
            last_ingress_update: SystemTime::now(),
            last_queue_length: 0,
            inner: Default::default(),
        }
    }

    fn update_aggregate_ingress_rate(&mut self, pkt: &Pkt) {
        if SystemTime::now().duration_since(self.last_ingress_update).unwrap().as_secs_f64() > 1.0 {
            self.last_ingress_update = SystemTime::now();

            let aggregates = get_aggregates(pkt, &self.ip_to_aggregates, self.lookup_on_src_ip);
            for aggregate in aggregates {
                if !(self.aggregate_to_update_and_ingress_rate.contains_key(&aggregate)) {
                    self.aggregate_to_update_and_ingress_rate.insert(aggregate.clone(), (SystemTime::now(), 0.0));
                }
                let (last_ingress_update, old_rate) = self.aggregate_to_update_and_ingress_rate.get(&aggregate).unwrap_or_else(|| panic!("Failed to get ingress rate for aggregate: {}", aggregate)).clone();
                let time_since_rate_calc = last_ingress_update.elapsed().unwrap().as_secs_f64();
                let mut new_rate = pkt.len() as f64 / time_since_rate_calc;
                new_rate = exponential_smooth(old_rate, new_rate, time_since_rate_calc, K);
                self.aggregate_to_update_and_ingress_rate.insert(aggregate.clone(), (SystemTime::now(), new_rate));
                debug!("Aggregate Stats, Time {}, Aggregate {}, Ingress Rate: {:?}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64(), aggregate, new_rate);
            }
        }
    }

    fn update_aggregate_egress_rate(&mut self, pkt: &Pkt) {
        if SystemTime::now().duration_since(self.last_egress_update).unwrap().as_secs_f64() > 1.0 {
            self.last_egress_update = SystemTime::now();
            
            let aggregates = get_aggregates(pkt, &self.ip_to_aggregates, self.lookup_on_src_ip);
            for aggregate in aggregates {
                if !(self.aggregate_to_update_and_egress_rate.contains_key(&aggregate)) {
                    self.aggregate_to_update_and_egress_rate.insert(aggregate.clone(), (SystemTime::now(), 0.0));
                }
                let (last_egress_update, old_rate) = self.aggregate_to_update_and_egress_rate.get(&aggregate).unwrap_or_else(|| panic!("Failed to get ingress rate for aggregate: {}", aggregate)).clone();
                let time_since_rate_calc = last_egress_update.elapsed().unwrap().as_secs_f64();
                let mut new_rate = pkt.len() as f64 / time_since_rate_calc;
                new_rate = exponential_smooth(old_rate, new_rate, time_since_rate_calc, K);
                self.aggregate_to_update_and_egress_rate.insert(aggregate.clone(), (SystemTime::now(), new_rate));
                debug!("Aggregate Stats, Time {}, Aggregate {}, Egress Rate: {:?}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64(), aggregate, new_rate);
            }
        }
    }

    fn should_drop(&mut self, p: &Pkt) -> bool {
        let aggregates = get_aggregates(p, &self.ip_to_aggregates, self.lookup_on_src_ip);
        // Find the last active aggregate in the list and use its drop probability.
        let mut last_active_agg : Option<String> = None;
        for aggregate in aggregates.iter().rev() {
            last_active_agg = Some(aggregate.clone());
            break;
            if self.shadow_buffer.is_constrained(aggregate) {
                last_active_agg = Some(aggregate.clone());
                break;
            }
        }
        match last_active_agg {
            Some(last_active_agg) => {
                if self.shadow_buffer.aggregate_occupancy.contains_key(&last_active_agg) {
                    let occupancy = self.shadow_buffer.occupancy(&last_active_agg) as f64;
                    if occupancy < 30.0 {
                        return false;
                    }
                    let weight_share = self.shadow_buffer.weight_share(&last_active_agg);
                    let drop_prob = 1.0 - (self.shadow_buffer.m_fair / occupancy) * weight_share;
                    debug!("Time {}, Src: {:?}, M_fair: {}, Occupancy: {}, Weight Share: {}, drop prob: {}, queue length: {}, aggregate: {}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64(), p.ip_hdr.source, self.shadow_buffer.m_fair, occupancy, weight_share, drop_prob, self.inner.len(), last_active_agg);
                    self.shadow_buffer.get_rand_f64() < drop_prob
                } else {
                    false
                }
            }
            None => {false}
        }
    }
}

impl Scheduler for HierarchicalApproximateFairDropping {
    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        self.shadow_buffer.sample(&p)?;
        self.update_aggregate_ingress_rate(&p);

        if self.shadow_buffer.should_update_mfair() {
            self.shadow_buffer.last_update_time = SystemTime::now();
            self.shadow_buffer.update_mfair(self.inner.len(), self.last_queue_length);
            self.last_queue_length = self.inner.len();
        }

        if !self.should_drop(&p) {
            self.inner.push_back(p.clone());
        }
        Ok(())
    }

    fn deq(&mut self) -> Result<Option<Pkt>, Report> {
        if self.inner.is_empty() {
            return Ok(None);
        }
        let p = self.inner.pop_front().unwrap();
        self.update_aggregate_egress_rate(&p);
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
            0.1, wt, true
        );

        (
            hwfq,
            u32::to_be_bytes(all_ips[0]),
            u32::to_be_bytes(all_ips[1]),
            u32::to_be_bytes(all_ips[2]),
        )
    }

    #[test]
    fn hafd_basic() {
        init();
        let (mut hwfq, b_ip, d_ip, e_ip) = make_test_tree();
        let dst_ip = [42, 2, 0, 0];
        let mut b_cnt = 0;
        let mut d_cnt = 0;
        let mut e_cnt = 0;

        // Now enqueue a bunch but enqueue 8 b for every 5 c and 3 d.
        let b_ingress_rate = 8;
        let d_ingress_rate = 5;
        let e_ingress_rate = 3;
        
        for _ in 0..10000 {
            for _ in 0..b_ingress_rate {
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
            }
            for _ in 0..d_ingress_rate {
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
            }
            for _ in 0..e_ingress_rate {
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

            // Attempt to dequeue 3 packets.
            for _ in 0..3 {
                match hwfq.deq() {
                    Ok(Some(p)) => {
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
                    Ok(None) => {},
                    Err(e) => panic!("error: {:?}", e),
                }
            }
        }

        // should be d + e ~= 2 * b, e ~= 2 * d
        dbg!(b_cnt, d_cnt, e_cnt);
        println!("b_cnt: {}, d_cnt: {}, e_cnt: {}", b_cnt, d_cnt, e_cnt);
        let sum_d_e = (d_cnt + e_cnt) as isize;
        // This ratio should be 2.0.
        let ratio_d_e_to_b = (sum_d_e as f64) / (b_cnt as f64);
        assert!((ratio_d_e_to_b - 2.0).abs() < 0.1);
        // This ratio should be 2.0.
        let ratio_e_to_d = (e_cnt as f64) / (d_cnt as f64);
        assert!((ratio_e_to_d - 2.0).abs() < 0.1);

        // Assert that each aggregate sent more than 100 packets.
        assert!(b_cnt > 100);
        assert!(d_cnt > 100);
        assert!(e_cnt > 100);
    }

    #[test]
    fn hafd_unconstrained() {
        init();
        let (mut hwfq, b_ip, d_ip, e_ip) = make_test_tree();
        let dst_ip = [42, 2, 0, 0];
        let mut b_cnt = 0;
        let mut d_cnt = 0;
        let mut e_cnt = 0;

        // Now enqueue a bunch but enqueue 8 b for every 5 c and 3 d.
        let b_ingress_rate = 2;
        let d_ingress_rate = 10;
        let e_ingress_rate = 10;

        let egress_rate = 9;
        
        for _ in 0..100000 {
            for _ in 0..b_ingress_rate {
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
            }
            for _ in 0..d_ingress_rate {
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
            }
            for _ in 0..e_ingress_rate {
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

            // Attempt to dequeue packets
            for _ in 0..egress_rate {
                match hwfq.deq() {
                    Ok(Some(p)) => {
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
                    Ok(None) => {},
                    Err(e) => panic!("error: {:?}", e),
                }
            }
        }

        dbg!(b_cnt, d_cnt, e_cnt);
        let expected_b_rate: f64 = b_ingress_rate as f64 / egress_rate as f64;
        let b_actual = b_cnt  as f64 / (b_cnt + d_cnt + e_cnt) as f64;


        assert!(((b_actual - expected_b_rate) / expected_b_rate).abs() > -0.1);
        
        // This ratio should be 2.0.
        let ratio_e_to_d = (e_cnt as f64) / (d_cnt as f64);
        assert!((ratio_e_to_d - 2.0).abs() < 0.15);

        // Assert that each aggregate sent more than 100 packets.
        assert!(b_cnt > 100);
        assert!(d_cnt > 100);
        assert!(e_cnt > 100);
    }

    #[test]
    fn hafd_high_rate() {
        init();
        let (mut hwfq, b_ip, d_ip, e_ip) = make_test_tree();
        let dst_ip = [42, 2, 0, 0];
        let mut b_cnt = 0;
        let mut d_cnt = 0;
        let mut e_cnt = 0;

        // Now enqueue a bunch but enqueue 8 b for every 5 c and 3 d.
        let b_ingress_rate = 80;
        let d_ingress_rate = 50;
        let e_ingress_rate = 30;
        
        for _ in 0..10000 {
            for _ in 0..b_ingress_rate {
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
            }
            for _ in 0..d_ingress_rate {
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
            }
            for _ in 0..e_ingress_rate {
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

            // Attempt to dequeue 3 packets.
            for _ in 0..3 {
                match hwfq.deq() {
                    Ok(Some(p)) => {
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
                    Ok(None) => {},
                    Err(e) => panic!("error: {:?}", e),
                }
            }
        }

        // should be d + e ~= 2 * b, e ~= 2 * d
        dbg!(b_cnt, d_cnt, e_cnt);
        println!("b_cnt: {}, d_cnt: {}, e_cnt: {}", b_cnt, d_cnt, e_cnt);
        let sum_d_e = (d_cnt + e_cnt) as isize;
        // This ratio should be 2.0.
        let ratio_d_e_to_b = (sum_d_e as f64) / (b_cnt as f64);
        assert!((ratio_d_e_to_b - 2.0).abs() < 0.1);
        // This ratio should be 2.0.
        let ratio_e_to_d = (e_cnt as f64) / (d_cnt as f64);
        assert!((ratio_e_to_d - 2.0).abs() < 0.1);

        // Assert that each aggregate sent more than 100 packets.
        assert!(b_cnt > 100);
        assert!(d_cnt > 100);
        assert!(e_cnt > 100);
    }

}
