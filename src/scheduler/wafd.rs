use super::Scheduler;
use crate::Pkt;
use crate::scheduler::common::WeightTree;
use color_eyre::eyre::Report;
use std::collections::HashMap;
use std::collections::VecDeque;
use tracing::debug;
use tracing::error;
use tracing::info;
use std::time::SystemTime;

const MAX_PACKETS : usize = 1000;

const ALPHA: f64 = 1.7;
const BETA: f64 = 1.8;
const K: f64 = 0.1;

const UPDATE_FREQUENCY: f64 = 160.0;

const TARGET_QUEUE_LENGTH: f64 = 50.0;

const MIN_M_FAIR: f64 = 10.0;
const MAX_M_FAIR: f64 = MAX_PACKETS as f64;

#[derive(Debug)]
pub struct ShadowBuffer {
    /// The probability that a packet is sampled into the shadow buffer.
    packet_sample_prob: f64,
    /// The maximum number of packets in the shadow buffer.
    max_packets: usize,
    /// The time of the last update to m_fair.
    last_update_time: SystemTime,
    m_fair: f64,
    ip_to_weight: HashMap<u32, f64>,
    ip_to_weight_share: HashMap<u32, f64>,
    /// The shadow buffer.
    inner: VecDeque<Pkt>,
}

fn exponential_smooth(old_value: f64, new_value: f64, time_since: f64, k: f64) -> f64 {
    // (1.0 - f64::powf(E, -time_since / k)) * new_value + f64::powf(E, -time_since / k) * old_value
    (old_value + new_value) / 2.0
}

impl ShadowBuffer {
    pub fn new(packet_sample_prob: f64, max_packets: usize, ip_to_weight: HashMap<u32, f64>) -> Self {
        Self {
            packet_sample_prob,
            max_packets,
            m_fair: 10.0,
            last_update_time: SystemTime::now(),
            ip_to_weight,
            ip_to_weight_share: HashMap::new(),
            inner: Default::default(),
        }
    }

    pub fn sample(&mut self, p: &Pkt) -> Result<(), Report> {
        self.update_weight_shares();
        if rand::random::<f64>() < self.packet_sample_prob {
            self.enq(p.clone())?;
        }
        Ok(())
    }

    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        // If we are at capacity pop the oldest packet.
        if self.inner.len() == self.max_packets {
            let _ = self.inner.pop_front();
        }
        self.update_weight_shares();
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

    pub fn update_mfair(&mut self, queue_length : usize, last_queue_length : usize) {
        self.m_fair = self.m_fair + ALPHA * (last_queue_length as f64 - TARGET_QUEUE_LENGTH) - BETA * (queue_length as f64 - TARGET_QUEUE_LENGTH);
    }

    pub fn should_update_mfair(&self) -> bool {
        let time_since_last_m_fair_update = self.last_update_time.elapsed().unwrap().as_secs_f64();
        time_since_last_m_fair_update > 1.0 / UPDATE_FREQUENCY
    }

    // Walks through the buffer and finds the total number of packets that share a source IP with the given packet.
    pub fn occupancy(&self, p: &Pkt) -> usize {
        let src_ip = p.ip_hdr.source;
        let mut count = 0;
        for pkt in &self.inner {
            if pkt.ip_hdr.source == src_ip {
                count += 1;
            }
        }
        count
    }

    pub fn total_weight(&self) -> f64 {
        let mut total_weight = 0.0;
        for (_, weight) in &self.ip_to_weight {
            total_weight += weight;
        }
        total_weight
    }

    pub fn update_weight_shares(&mut self) {
        let total_weight = self.total_weight();
        for (ip, weight) in &self.ip_to_weight {
            self.ip_to_weight_share.insert(*ip, weight / total_weight);
        }
    }
}
/// Implement an approximate fair dropping [`Scheduler`].
///
/// See [`ApproximateFairDropping::new`].
#[derive(Debug)]
pub struct WeightedApproximateFairDropping {
    shadow_buffer: ShadowBuffer,
    last_queue_length: usize,
    flow_to_update_and_ingress_rate: HashMap<[u8; 4], (SystemTime, f64)>,
    flow_to_update_and_egress_rate: HashMap<[u8; 4], (SystemTime, f64)>,
    last_egress_update: SystemTime,
    last_ingress_update: SystemTime,
    inner: VecDeque<Pkt>,
}

impl WeightedApproximateFairDropping {
    pub fn new (
        packet_sample_prob: f64,
        tree: WeightTree,
    ) -> Self {
        let mut ip_to_weight = std::collections::HashMap::new();

        // Form the weight map from the tree.
        fn weight_tree_helper(
            tree: WeightTree,
            weight_map: &mut HashMap<u32, f64>,
            child_ip: Option<u32>,
        ) {
            match tree {
                WeightTree::Leaf { weight, .. } => {
                    // debug!("Weight: {}", weight);
                    weight_map.insert(child_ip.unwrap(), weight as f64);
                }
                WeightTree::NonLeaf {
                    weight,
                    ips,
                    children,
                } => {
                    for (child, child_ips) in children.iter().zip(ips.iter()) {
                        if let Some(child) = child {
                            weight_tree_helper(
                                *child.clone(),
                                weight_map,
                                Some(child_ips.clone()[0])
                            );
                        }
                    }
                }
            }
        }
        weight_tree_helper(
            tree,
            &mut ip_to_weight,
            None
        );

        info!("Weight map");
        for (k, v) in ip_to_weight.clone() {
            info!("  {}: {}", k, v);
        }
        let shadow_buffer = ShadowBuffer::new(packet_sample_prob, MAX_PACKETS, ip_to_weight);

        Self {
            shadow_buffer,
            last_queue_length: 0,
            flow_to_update_and_ingress_rate: HashMap::new(),
            flow_to_update_and_egress_rate: HashMap::new(),
            last_egress_update: SystemTime::now(),
            last_ingress_update: SystemTime::now(),
            inner: Default::default(),
        }
    }

    fn should_drop(&mut self, p: &Pkt) -> bool {
        let occupancy = self.shadow_buffer.occupancy(p) as f64;
        let weight_share = self.shadow_buffer.ip_to_weight_share.get(&u32::from_be_bytes(p.ip_hdr.source.clone())).unwrap();
        let drop_prob = 1.0 - (self.shadow_buffer.m_fair / occupancy) * weight_share;
        debug!("Time {}, Src: {:?}, MFair: {}, Occupancy: {}, drop prob: {}, queue length: {}, weight share: {}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64(), p.ip_hdr.source, self.shadow_buffer.m_fair, occupancy, drop_prob, self.inner.len(), weight_share);
        rand::random::<f64>() < drop_prob
    }

    fn update_ingress_rate(&mut self, p: &Pkt) {
        if SystemTime::now().duration_since(self.last_ingress_update).unwrap().as_secs_f64() > 1.0 {
            self.last_ingress_update = SystemTime::now();

            if !(self.flow_to_update_and_ingress_rate.contains_key(&p.ip_hdr.source)) {
                self.flow_to_update_and_ingress_rate.insert(p.ip_hdr.source, (SystemTime::now(), 0.0));
            }
            let (last_ingress_update, old_rate) = self.flow_to_update_and_ingress_rate.get(&p.ip_hdr.source).unwrap_or_else(|| panic!("Failed to get ingress rate for flow: {:?}", p.ip_hdr.source.clone())).clone();
            let time_since_rate_calc = last_ingress_update.elapsed().unwrap().as_secs_f64();
            let mut new_rate = p.len() as f64 / time_since_rate_calc;
            new_rate = exponential_smooth(old_rate, new_rate, time_since_rate_calc, K);
            self.flow_to_update_and_ingress_rate.insert(p.ip_hdr.source, (SystemTime::now(), new_rate));
            debug!("Aggregate Stats, Time {}, Flow {:?}, Ingress Rate: {:?}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64(), p.ip_hdr.source.clone(), new_rate);
        }
    }

    fn update_egress_rate(&mut self, p: &Pkt) {
        if SystemTime::now().duration_since(self.last_egress_update).unwrap().as_secs_f64() > 1.0 {
            self.last_egress_update = SystemTime::now();

            if !(self.flow_to_update_and_egress_rate.contains_key(&p.ip_hdr.source)) {
                self.flow_to_update_and_egress_rate.insert(p.ip_hdr.source, (SystemTime::now(), 0.0));
            }
            let (last_egress_update, old_rate) = self.flow_to_update_and_egress_rate.get(&p.ip_hdr.source).unwrap_or_else(|| panic!("Failed to get egress rate for flow: {:?}", p.ip_hdr.source.clone())).clone();
            let time_since_rate_calc = last_egress_update.elapsed().unwrap().as_secs_f64();
            let mut new_rate = p.len() as f64 / time_since_rate_calc;
            new_rate = exponential_smooth(old_rate, new_rate, time_since_rate_calc, K);
            self.flow_to_update_and_egress_rate.insert(p.ip_hdr.source, (SystemTime::now(), new_rate));
            debug!("Aggregate Stats, Time {}, Flow {:?}, Egress Rate: {:?}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64(), p.ip_hdr.source.clone(), new_rate);
        }
    }
}

impl Scheduler for WeightedApproximateFairDropping {

    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        let res = self.shadow_buffer.sample(&p);
        if let Err(e) = res {
            error!("Failed to sample packet: {:?}", p);
            return Err(e);
        }

        self.update_ingress_rate(&p);

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
        self.update_egress_rate(&p);
        Ok(Some(p))
    }

    fn dbg(&self) {
        debug!(?self.inner);
    }
}

// #[cfg(test)]
// mod t {
//     use crate::{Pkt, Scheduler};

//     fn init() {
//         use std::sync::Once;
//         static INIT: Once = Once::new();

//         INIT.call_once(|| {
//             tracing_subscriber::fmt::init();
//             color_eyre::install().unwrap();
//         })
//     }

//     fn make_test_tree() -> (
//         super::WeightedApproximateFairDropping,
//         [u8; 4],
//         [u8; 4],
//         [u8; 4],
//     ) {
//         let all_ips = [
//             u32::from_be_bytes([42, 0, 0, 0]),
//             u32::from_be_bytes([42, 1, 1, 1]),
//             u32::from_be_bytes([42, 1, 2, 1]),
//         ];
//         let mut ip_to_weight = std::collections::HashMap::new();
//         ip_to_weight.insert(u32::from_be_bytes([42, 0, 0, 0]), 1.0);
//         ip_to_weight.insert(u32::from_be_bytes([42, 1, 1, 1]), 2.0);
//         let hwfq = super::WeightedApproximateFairDropping::new(
//             0.1,
//             ip_to_weight,
//         );

//         (
//             hwfq,
//             u32::to_be_bytes(all_ips[0]),
//             u32::to_be_bytes(all_ips[1]),
//             u32::to_be_bytes(all_ips[2]),
//         )
//     }

//     #[test]
//     fn wafd_simple() {
//         init();
//         let (mut hwfq, b_ip, c_ip, d_ip) = make_test_tree();
//         let dst_ip = [42, 2, 0, 0];
//         let mut b_cnt = 0;
//         let mut c_cnt = 0;

//         // Now enqueue a bunch but enqueue 8 b for every 1 c.
//         for _ in 0..10000 {
//             for _ in 0..8 {
//                 hwfq.enq(Pkt {
//                     ip_hdr: etherparse::Ipv4Header::new(
//                         100,
//                         64,
//                         etherparse::IpNumber::Tcp,
//                         b_ip,
//                         dst_ip,
//                     ),
//                     buf: vec![0u8; 100],
//                 })
//                 .unwrap();
//             }
//             for _ in 0..2 {
//                 hwfq.enq(Pkt {
//                     ip_hdr: etherparse::Ipv4Header::new(
//                         100,
//                         64,
//                         etherparse::IpNumber::Tcp,
//                         c_ip,
//                         dst_ip,
//                     ),
//                     buf: vec![0u8; 100],
//                 })
//                 .unwrap();
//             }

//             // Attempt to dequeue 3 packets.
//             for _ in 0..3 {
//                 match hwfq.deq() {
//                     Ok(Some(p)) => {
//                         if p.ip_hdr.source == b_ip {
//                             b_cnt += 1;
//                         } else if p.ip_hdr.source == c_ip {
//                             c_cnt += 1;
//                         } else {
//                             panic!("unknown ip");
//                         }
//                     }
//                     Ok(None) => {},
//                     Err(e) => panic!("error: {:?}", e),
//                 }
//             }
//         }

//         dbg!(b_cnt, c_cnt);
//         let ratio = c_cnt as f64 / b_cnt as f64;
//         assert!(ratio < 2.1 && ratio > 1.9);

//         // Also ensure we sent more than 100 packets from each source.
//         assert!(b_cnt > 100);
//         assert!(c_cnt > 100);
//     }

//     #[test]
//     fn wafd_more() {
//         init();

//         let b_ip = [42, 0, 0, 0];
//         let c_ip = [42, 1, 1, 1];
//         let d_ip = [42, 1, 2, 1];

//         let mut ip_to_weight = std::collections::HashMap::new();
//         ip_to_weight.insert(u32::from_be_bytes([42, 0, 0, 0]), 2.0);
//         ip_to_weight.insert(u32::from_be_bytes([42, 1, 1, 1]), 3.0);
//         ip_to_weight.insert(u32::from_be_bytes([42, 1, 2, 1]), 5.0);

//         let mut hwfq = super::WeightedApproximateFairDropping::new(
//             0.1,
//             ip_to_weight,
//         );

//         let dst_ip = [42, 2, 0, 0];
//         let mut b_cnt = 0;
//         let mut c_cnt = 0;
//         let mut d_cnt = 0;

//         // Now enqueue a bunch but enqueue 8 b for every 5 c and 3 d.
//         let b_ingress_rate = 8;
//         let c_ingress_rate = 5;
//         let d_ingress_rate = 3;
//         for _ in 0..10000 {
//             for _ in 0..b_ingress_rate {
//                 hwfq.enq(Pkt {
//                     ip_hdr: etherparse::Ipv4Header::new(
//                         100,
//                         64,
//                         etherparse::IpNumber::Tcp,
//                         b_ip,
//                         dst_ip,
//                     ),
//                     buf: vec![0u8; 100],
//                 })
//                 .unwrap();
//             }
//             for _ in 0..c_ingress_rate {
//                 hwfq.enq(Pkt {
//                     ip_hdr: etherparse::Ipv4Header::new(
//                         100,
//                         64,
//                         etherparse::IpNumber::Tcp,
//                         c_ip,
//                         dst_ip,
//                     ),
//                     buf: vec![0u8; 100],
//                 })
//                 .unwrap();
//             }
//             for _ in 0..d_ingress_rate {
//                 hwfq.enq(Pkt {
//                     ip_hdr: etherparse::Ipv4Header::new(
//                         100,
//                         64,
//                         etherparse::IpNumber::Tcp,
//                         d_ip,
//                         dst_ip,
//                     ),
//                     buf: vec![0u8; 100],
//                 })
//                 .unwrap();
//             }

//             // Attempt to dequeue 3 packets.
//             for _ in 0..3 {
//                 match hwfq.deq() {
//                     Ok(Some(p)) => {
//                         if p.ip_hdr.source == b_ip {
//                             b_cnt += 1;
//                         } else if p.ip_hdr.source == c_ip {
//                             c_cnt += 1;
//                         } else if p.ip_hdr.source == d_ip {
//                             d_cnt += 1;
//                         } else {
//                             panic!("unknown ip");
//                         }
//                     }
//                     Ok(None) => {},
//                     Err(e) => panic!("error: {:?}", e),
//                 }
//             }
//         }

//         dbg!(b_cnt, c_cnt, d_cnt);
//         let ratio_b_to_c = b_cnt as f64 / c_cnt as f64;
//         let ratio_c_to_d = c_cnt as f64 / d_cnt as f64;
//         let ratio_b_to_d = b_cnt as f64 / d_cnt as f64;

//         assert!(ratio_b_to_c < (2.0 / 3.0) * 1.1 && ratio_b_to_c > (2.0 / 3.0) * 0.9);
//         assert!(ratio_c_to_d < (3.0 / 5.0) * 1.1 && ratio_c_to_d > (3.0 / 5.0) * 0.9);
//         assert!(ratio_b_to_d < (2.0 / 5.0) * 1.1 && ratio_b_to_d > (2.0 / 5.0) * 0.9);

//         // Also ensure we sent more than 100 packets from each source.
//         assert!(b_cnt > 100);
//         assert!(c_cnt > 100);
//         assert!(d_cnt > 100);
//     }
// }
