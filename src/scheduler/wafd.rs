use super::Scheduler;
use crate::Pkt;
use color_eyre::eyre::Report;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use tracing::debug;
use tracing::error;
use std::time::SystemTime;
use std::f64::consts::E;

const MAX_PACKETS : usize = 500;

const K: f64 = 0.1;

fn exponential_smooth(old_value: f64, new_value: f64, time_since: f64, k: f64) -> f64 {
    (1.0 - f64::powf(E, -time_since / k)) * new_value + f64::powf(E, -time_since / k) * old_value
}

#[derive(Debug)]
pub struct ShadowBuffer {
    /// The probability that a packet is sampled into the shadow buffer.
    packet_sample_prob: f64,
    /// The maximum number of packets in the shadow buffer.
    max_packets: usize,
    /// The shadow buffer.
    inner: VecDeque<Pkt>,
}

impl ShadowBuffer {
    pub fn new(packet_sample_prob: f64, max_packets: usize) -> Self {
        Self {
            packet_sample_prob,
            max_packets,
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
        if self.inner.len() == self.max_packets {
            let _ = self.inner.pop_front();
        }
        self.inner.push_back(p);

        Ok(())
    }

    /// Gets the total number of packets in the shadow buffer.
    pub fn size(&self) -> usize {
        self.inner.len()
    }

    pub fn total_weight(&self, ip_to_weight: &HashMap<u32, f64>) -> f64 {
        let mut total_weight = 0.0;
        let src_ips_seen = self.inner.iter().map(|p| p.ip_hdr.source).collect::<HashSet<[u8; 4]>>();
        for src_ip in src_ips_seen {
            total_weight += ip_to_weight.get(&u32::from_be_bytes(src_ip)).unwrap_or(&1.0);
        }
        total_weight
    }

    fn dbg(&self) {
        debug!(?self.inner);
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
}

/// Implement an approximate fair dropping [`Scheduler`].
///
/// See [`ApproximateFairDropping::new`].
#[derive(Debug)]
pub struct WeightedApproximateFairDropping {
    shadow_buffer: ShadowBuffer,
    ingress_rate: f64,
    last_update_time: SystemTime,
    capacity: f64,
    last_capacity_update_time: SystemTime,
    ip_to_weight: HashMap<u32, f64>,
    inner: VecDeque<Pkt>,
}

impl WeightedApproximateFairDropping {
    pub fn new (
        packet_sample_prob: f64,
        ip_to_weight: HashMap<u32, f64>,
    ) -> Self {

        let shadow_buffer = ShadowBuffer::new(packet_sample_prob, MAX_PACKETS);

        Self {
            shadow_buffer,
            ingress_rate: 0.0,
            last_update_time: SystemTime::now(),
            capacity: 0.0,
            last_capacity_update_time: SystemTime::now(),
            ip_to_weight,
            inner: Default::default(),
        }
    }

    fn should_drop(&mut self, p: &Pkt) -> bool {
        let occupancy = self.shadow_buffer.occupancy(p) as f64;
        let b = self.shadow_buffer.size() as f64;
        let normalized_weight = self.ip_to_weight.get(&u32::from_be_bytes(p.ip_hdr.source)).unwrap() / self.shadow_buffer.total_weight(&self.ip_to_weight);
        let drop_prob = 1.0 - ((normalized_weight * b) / occupancy) * (self.capacity / self.ingress_rate);
        debug!("IP {:?}",
            p.ip_hdr.source
        );
        debug!("  occupancy: {}", occupancy);
        debug!("  b: {}", b);
        debug!("  normalized_weight: {}", normalized_weight);
        debug!("  capacity: {}", self.capacity);
        debug!("  ingress_rate: {}", self.ingress_rate);
        debug!("  drop_prob: {}", drop_prob);
        rand::random::<f64>() < drop_prob
    }

    fn update_ingress_rate(&mut self, p: &Pkt) {
        let time_since_rate_calc = self.last_update_time.elapsed().unwrap().as_secs_f64();
        let new_rate = p.len() as f64 / time_since_rate_calc;
        self.ingress_rate = exponential_smooth(self.ingress_rate, new_rate, time_since_rate_calc, K);
        self.last_update_time = SystemTime::now();
    }

    fn update_capacity(&mut self, p: &Pkt) {
        let time_since_rate_calc = self.last_capacity_update_time.elapsed().unwrap().as_secs_f64();
        let new_rate = p.len() as f64 / time_since_rate_calc;
        self.capacity = exponential_smooth(self.capacity, new_rate, time_since_rate_calc, K);
        self.last_capacity_update_time = SystemTime::now();
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
        self.update_capacity(&p);
        Ok(Some(p))
    }

    fn dbg(&self) {
        debug!(?self.inner);
    }
}

#[cfg(test)]
mod t {
    use crate::{Pkt, Scheduler};

    fn init() {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            tracing_subscriber::fmt::init();
            color_eyre::install().unwrap();
        })
    }

    fn make_test_tree() -> (
        super::WeightedApproximateFairDropping,
        [u8; 4],
        [u8; 4],
        [u8; 4],
    ) {
        let all_ips = [
            u32::from_be_bytes([42, 0, 0, 0]),
            u32::from_be_bytes([42, 1, 1, 1]),
            u32::from_be_bytes([42, 1, 2, 1]),
        ];
        let mut ip_to_weight = std::collections::HashMap::new();
        ip_to_weight.insert(u32::from_be_bytes([42, 0, 0, 0]), 1.0);
        ip_to_weight.insert(u32::from_be_bytes([42, 1, 1, 1]), 2.0);
        let hwfq = super::WeightedApproximateFairDropping::new(
            0.1,
            ip_to_weight,
        );

        (
            hwfq,
            u32::to_be_bytes(all_ips[0]),
            u32::to_be_bytes(all_ips[1]),
            u32::to_be_bytes(all_ips[2]),
        )
    }

    #[test]
    fn wafd_simple() {
        init();
        let (mut hwfq, b_ip, c_ip, d_ip) = make_test_tree();
        let dst_ip = [42, 2, 0, 0];
        let mut b_cnt = 0;
        let mut c_cnt = 0;

        // Now enqueue a bunch but enqueue 8 b for every 1 c.
        for _ in 0..10000 {
            for _ in 0..8 {
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
            for _ in 0..2 {
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
            }

            // Attempt to dequeue 3 packets.
            for _ in 0..3 {
                match hwfq.deq() {
                    Ok(Some(p)) => {
                        if p.ip_hdr.source == b_ip {
                            b_cnt += 1;
                        } else if p.ip_hdr.source == c_ip {
                            c_cnt += 1;
                        } else {
                            panic!("unknown ip");
                        }
                    }
                    Ok(None) => {},
                    Err(e) => panic!("error: {:?}", e),
                }
            }
        }

        dbg!(b_cnt, c_cnt);
        let ratio = c_cnt as f64 / b_cnt as f64;
        assert!(ratio < 2.1 && ratio > 1.9);

        // Also ensure we sent more than 100 packets from each source.
        assert!(b_cnt > 100);
        assert!(c_cnt > 100);
    }

    #[test]
    fn wafd_more() {
        init();

        let b_ip = [42, 0, 0, 0];
        let c_ip = [42, 1, 1, 1];
        let d_ip = [42, 1, 2, 1];

        let mut ip_to_weight = std::collections::HashMap::new();
        ip_to_weight.insert(u32::from_be_bytes([42, 0, 0, 0]), 2.0);
        ip_to_weight.insert(u32::from_be_bytes([42, 1, 1, 1]), 3.0);
        ip_to_weight.insert(u32::from_be_bytes([42, 1, 2, 1]), 5.0);

        let mut hwfq = super::WeightedApproximateFairDropping::new(
            0.1,
            ip_to_weight,
        );

        let dst_ip = [42, 2, 0, 0];
        let mut b_cnt = 0;
        let mut c_cnt = 0;
        let mut d_cnt = 0;

        // Now enqueue a bunch but enqueue 8 b for every 5 c and 3 d.
        let b_ingress_rate = 8;
        let c_ingress_rate = 5;
        let d_ingress_rate = 3;
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
            for _ in 0..c_ingress_rate {
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

            // Attempt to dequeue 3 packets.
            for _ in 0..3 {
                match hwfq.deq() {
                    Ok(Some(p)) => {
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
                    Ok(None) => {},
                    Err(e) => panic!("error: {:?}", e),
                }
            }
        }

        dbg!(b_cnt, c_cnt, d_cnt);
        let ratio_b_to_c = b_cnt as f64 / c_cnt as f64;
        let ratio_c_to_d = c_cnt as f64 / d_cnt as f64;
        let ratio_b_to_d = b_cnt as f64 / d_cnt as f64;

        assert!(ratio_b_to_c < (2.0 / 3.0) * 1.1 && ratio_b_to_c > (2.0 / 3.0) * 0.9);
        assert!(ratio_c_to_d < (3.0 / 5.0) * 1.1 && ratio_c_to_d > (3.0 / 5.0) * 0.9);
        assert!(ratio_b_to_d < (2.0 / 5.0) * 1.1 && ratio_b_to_d > (2.0 / 5.0) * 0.9);

        // Also ensure we sent more than 100 packets from each source.
        assert!(b_cnt > 100);
        assert!(c_cnt > 100);
        assert!(d_cnt > 100);
    }
}
