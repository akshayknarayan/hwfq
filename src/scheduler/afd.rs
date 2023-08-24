use super::Scheduler;
use crate::Pkt;
use color_eyre::eyre::Report;
use std::collections::HashMap;
use std::collections::VecDeque;
use tracing::debug;
use tracing::info;
use tracing::error;
use std::time::SystemTime;
use crate::scheduler::common::WeightTree;
use crate::scheduler::common::parse_ip;

const MAX_PACKETS : usize = 500;
const IDEAL_QUEUE_LENGTH : f64 = 100.0;

const M_FAIR_UPDATES_PER_SECOND : f64 = 160.0;

const ALPHA : f64 = 1.7;
const BETA : f64 = 1.8;

// Hashes a vector of IPs to a string aggregate name.
fn ip_set_to_agg_name(ips: &[Vec<u32>]) -> String {
    let mut new_ips = ips.clone().to_vec();
    new_ips.sort();
    let agg_name = new_ips.iter().map(|ip| ip.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(".")).collect::<Vec<String>>().join("_");
    agg_name
}

fn get_aggregates(packet: &Pkt, ip_to_aggregates: &HashMap<u32, Vec<String>>) -> Vec<String> {
    let src_ip = packet.ip_hdr.source;
    
    // Turn the source IP into a String joined with periods.
    let new_src_ip = format!(
        "{}.{}.{}.{}",
        src_ip[0], src_ip[1], src_ip[2], src_ip[3]
    );

    debug!("New src ip: {} from {:?}", new_src_ip, src_ip);

    let parsed_ip = parse_ip(new_src_ip.as_str()).expect("Failed to parse IP");
    //info!("Parsed IP: {}", parsed_ip);
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

    pub fn num_unique_flows(&self) -> usize {
        let src_ips_seen = self.inner.iter().map(|p| p.ip_hdr.source).collect::<Vec<[u8; 4]>>();
        let mut unique_src_ips = vec![];
        for src_ip in src_ips_seen {
            if !unique_src_ips.contains(&src_ip) {
                unique_src_ips.push(src_ip);
            }
        }
        unique_src_ips.len()
    }

    fn dbg(&self) {
        debug!(?self.inner);
    }
}

/// Implement an approximate fair dropping [`Scheduler`].
///
/// See [`ApproximateFairDropping::new`].
#[derive(Debug)]
pub struct ApproximateFairDropping {
    aggregate_to_weight: HashMap<String, f64>,
    aggregate_to_weight_share: HashMap<String, f64>,
    aggregate_to_siblings: HashMap<String, Vec<String>>,
    /// Maps from a single IP to the list of aggregates it belongs to, from root to leaf.
    ip_to_aggregates: HashMap<u32, Vec<String>>,
    shadow_buffer: ShadowBuffer,
    m_fair: f64,
    last_queue_length: f64,
    last_update_time: SystemTime,
    inner: VecDeque<Pkt>,
}

impl ApproximateFairDropping {
    pub fn new (
        packet_sample_prob: f64,
        tree: WeightTree
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
                    debug!("LEAF IPS: {:?}", ips);
                    debug!("LAEF Weight: {}", weight);
                    let ip_array = [ips.clone()];
                    let agg = ip_set_to_agg_name(&ip_array);
                    let all_aggs = vec![agg.clone()];
                    weight_map.insert(agg.clone(), weight as f64);
                    ip_to_aggregates.insert(ips[0], all_aggs);
                }
                WeightTree::NonLeaf { weight, ips, children} => {
                    // Print out the ips.
                    debug!("IPS: {:?}", ips);
                    debug!("Weight: {}", weight);
                    let agg = ip_set_to_agg_name(&ips);
                    if !aggregate_to_siblings.contains_key(&agg) {
                        aggregate_to_siblings.insert(agg.clone(), vec![]);
                    }
                    weight_map.insert(agg.clone(), weight as f64);
                    let mut children_aggregates = vec![];
                    for i in 0..children.len() {
                        let child = children.get(i).unwrap();
                        let child_ips = ips[i].clone();
                        if let Some(child) = child {
                            weight_tree_helper(*child.clone(), weight_map, ip_to_aggregates, aggregate_to_siblings, Some(child_ips.clone()));
                            let new_child = child.clone();
                            debug!("Matching child");
                            match new_child.as_ref() {
                                WeightTree::Leaf { weight: _, ips: _} => {
                                    debug!("Matched as leaf");
                                    let ip_array = [child_ips.clone()];
                                    let agg = ip_set_to_agg_name(&ip_array);
                                    children_aggregates.push(agg);
                                }
                                WeightTree::NonLeaf { weight: _, ips: _, children: _} => {
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
                        let siblings = children_aggregates.clone().into_iter().filter(|x| x != &child_agg).collect::<Vec<String>>();
                        aggregate_to_siblings.insert(child_agg, siblings);
                    }
                }
            }
        }
        weight_tree_helper(tree, &mut weight_map, &mut ip_to_aggregates, &mut aggregate_to_siblings, None);

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

        let shadow_buffer = ShadowBuffer::new(packet_sample_prob, MAX_PACKETS, ip_to_aggregates.clone());

        Self {
            aggregate_to_weight: weight_map,
            aggregate_to_weight_share: HashMap::new(),
            aggregate_to_siblings,
            ip_to_aggregates,
            shadow_buffer,
            m_fair: 10000.0,
            last_queue_length: 0.0,
            last_update_time: SystemTime::now(),
            inner: Default::default(),
        }
    }

    fn update_mfair(&mut self) {
        let queue_len = self.inner.len() as f64;
        self.m_fair = self.m_fair + ALPHA * (self.last_queue_length - IDEAL_QUEUE_LENGTH) - BETA * (queue_len - IDEAL_QUEUE_LENGTH);
        debug!("Queue length: {}", queue_len);
        debug!("Mfair: {}", self.m_fair);
    }

    fn update_weight_shares(&mut self, pkt: &Pkt) {
        let mut weight_share = 1.0;
        let aggregates = get_aggregates(&pkt, &self.ip_to_aggregates);
        debug!("Updating drop probs");
        for aggregate in aggregates {
            self.aggregate_to_weight_share.insert(aggregate.clone(), 1.0);
            // debug!("  Aggregate: {}", aggregate);
            // if !self.is_active(&aggregate) {
            //     continue;
            // }
            // let weight = self.aggregate_to_weight.get(&aggregate).expect(format!("Failed to get weight for aggregate: {}", aggregate).as_str()).clone();
            // let total_active_weight = self.get_total_active_weight(&aggregate);
            // weight_share *= weight / total_active_weight;
            // self.aggregate_to_weight_share.insert(aggregate.clone(), weight_share);
            // debug!("    Weight share: {}", weight_share);
            // debug!("    Weight: {}", weight);
            // debug!("    Total active weight: {}", total_active_weight);
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
                !self.aggregate_to_weight_share.contains_key(&aggregate) ||
                !self.aggregate_to_weight.contains_key(&aggregate) {
                continue;
            }
            let weight_share = self.aggregate_to_weight_share.get(&aggregate).expect(format!("Failed to get weight share for aggregate: {}", aggregate).as_str());
            let occupancy = self.shadow_buffer.aggregate_occupancy.get(&aggregate).expect(format!("Failed to get occupancy for aggregate: {}", aggregate).as_str()).clone() as f64;
            if occupancy == 0.0 {
                continue;
            }
            // let drop_prob = 1.0 - (weight_share) *
            //                     (self.m_fair / occupancy);
            let num_unique_flows = self.shadow_buffer.num_unique_flows() as f64;
            let expected_number_of_packets = self.shadow_buffer.get_total_packets() as f64 / num_unique_flows;
            let drop_prob = 1.0 - (weight_share) *
                                (expected_number_of_packets / occupancy);
            debug!("Aggregate: {} drop prob: {}", aggregate, drop_prob);
            debug!("  Weight share: {}", weight_share);
            debug!("  Occupancy: {}", occupancy);
            debug!("  Mfair: {}", self.m_fair);
            debug!("  queue length: {}", self.inner.len());
            debug!("  shadow length: {}", self.shadow_buffer.get_total_packets());
            debug!("  num unique flows: {}", num_unique_flows);
            debug!("  drop_prob: {}", drop_prob);
            if rand::random::<f64>() < drop_prob {
                // assert!(aggregate == "704643072");
                return true;
            }
        }
        return false;
    }
}

impl Scheduler for ApproximateFairDropping {
    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        let res = self.shadow_buffer.sample(&p);
        if let Err(e) = res {
            error!("Failed to sample packet: {:?}", p);
            return Err(e);
        }

        if self.last_update_time.elapsed().unwrap().as_secs_f64() > 1.0 / M_FAIR_UPDATES_PER_SECOND {
            self.update_mfair();
            self.last_update_time = SystemTime::now();
        }

        self.update_weight_shares(&p);

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
        super::ApproximateFairDropping,
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
            .add_child(vec![all_ips[1]], WeightTree::leaf(1)) // "C"
            .unwrap()
            .add_child(vec![all_ips[2]], WeightTree::leaf(1)) // "D"
            .unwrap();
        let hwfq = super::ApproximateFairDropping::new(
            0.1, wt
        );

        (
            hwfq,
            u32::to_be_bytes(all_ips[0]),
            u32::to_be_bytes(all_ips[1]),
            u32::to_be_bytes(all_ips[2]),
        )
    }

    #[test]
    fn afd_basic() {
        init();
        let (mut hwfq, b_ip, c_ip, d_ip) = make_test_tree();
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
                    c_ip,
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
        }
        
        let mut b_cnt = 0;
        let mut c_cnt = 0;
        let mut d_cnt = 0;
        for _ in 0..hwfq.inner.len() {
            let p = hwfq.deq().unwrap().unwrap();
            if p.ip_hdr.source == b_ip {
                b_cnt += 1;
            } else if p.ip_hdr.source == c_ip {
                c_cnt += 1;
            } else if p.ip_hdr.source == d_ip {
                d_cnt += 1;
            } else {
                panic!("unknown ip");
            }
        }

        // should be d + e ~= 2 * b, e ~= 2 * d
        dbg!(b_cnt, c_cnt, d_cnt);
        assert!(((b_cnt - c_cnt) as isize).abs() < 5);
        assert!(((b_cnt - d_cnt) as isize).abs() < 5);
        assert!(((d_cnt - c_cnt) as isize).abs() < 5);
    }

    #[test]
    fn afd_two_to_one() {
        init();
        let (mut hwfq, b_ip, c_ip, d_ip) = make_test_tree();
        let dst_ip = [42, 2, 0, 0];

        // for _ in 0..500 {
        //     hwfq.enq(Pkt {
        //         ip_hdr: etherparse::Ipv4Header::new(
        //             100,
        //             64,
        //             etherparse::IpNumber::Tcp,
        //             b_ip,
        //             dst_ip,
        //         ),
        //         buf: vec![0u8; 100],
        //     }).unwrap();
        // }
        // Now enqueue a bunch but enqueue 2 b for every 1 c and 2 b for every 1 d.
        for _ in 0..1000 {
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
                    c_ip,
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
        }
        let mut b_cnt = 0;
        let mut c_cnt = 0;
        let mut d_cnt = 0;
        for _ in 0..500 {
            let p = hwfq.deq().unwrap().unwrap();
        }
        for _ in 0..500 {
            let p = hwfq.deq().unwrap().unwrap();
            if p.ip_hdr.source == b_ip {
                b_cnt += 1;
            } else if p.ip_hdr.source == c_ip {
                c_cnt += 1;
            } else if p.ip_hdr.source == d_ip {
                d_cnt += 1;
            } else {
                panic!("unknown ip");
            }
        }

        // should be b ~= c ~= d
        dbg!(b_cnt, c_cnt, d_cnt);
        assert!(((b_cnt - c_cnt) as isize).abs() < 5);
        assert!(((b_cnt - d_cnt) as isize).abs() < 5);
        assert!(((d_cnt - c_cnt) as isize).abs() < 5);
    }
}
