use super::Scheduler;
use crate::Pkt;
use color_eyre::eyre::Report;
use std::collections::VecDeque;
use tracing::debug;
use tracing::error;
use std::time::SystemTime;
use std::collections::HashMap;
use std::f64::consts::E;

const MAX_PACKETS : usize = 200;

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
    /// The shadow buffer.
    inner: VecDeque<Pkt>,
}

fn exponential_smooth(old_value: f64, new_value: f64, time_since: f64, k: f64) -> f64 {
    // (1.0 - f64::powf(E, -time_since / k)) * new_value + f64::powf(E, -time_since / k) * old_value
    (old_value + new_value) / 2.0
}

impl ShadowBuffer {
    pub fn new(packet_sample_prob: f64, max_packets: usize) -> Self {
        Self {
            packet_sample_prob,
            max_packets,
            m_fair: 0.0,
            last_update_time: SystemTime::now(),
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

    fn dbg(&self) {
        debug!(?self.inner);
    }

    pub fn update_mfair(&mut self, queue_length : usize, last_queue_length : usize) {
        self.m_fair = self.m_fair + ALPHA * (last_queue_length as f64 - TARGET_QUEUE_LENGTH) - BETA * (queue_length as f64 - TARGET_QUEUE_LENGTH);
        // self.clamp_m_fair();
    }

    pub fn should_update_mfair(&self) -> bool {
        let time_since_last_m_fair_update = self.last_update_time.elapsed().unwrap().as_secs_f64();
        time_since_last_m_fair_update > 1.0 / UPDATE_FREQUENCY
    }

    fn clamp_m_fair(&mut self) {
        if self.m_fair < MIN_M_FAIR {
            self.m_fair = MIN_M_FAIR;
        } else if self.m_fair > MAX_M_FAIR {
            self.m_fair = MAX_M_FAIR;
        }
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
pub struct ApproximateFairDropping {
    shadow_buffer: ShadowBuffer,
    last_queue_length: usize,
    flow_to_update_and_ingress_rate: HashMap<[u8; 4], (SystemTime, f64)>,
    flow_to_update_and_egress_rate: HashMap<[u8; 4], (SystemTime, f64)>,
    inner: VecDeque<Pkt>,
}

impl ApproximateFairDropping {
    pub fn new (
        packet_sample_prob: f64
    ) -> Self {

        let shadow_buffer = ShadowBuffer::new(packet_sample_prob, MAX_PACKETS);

        Self {
            shadow_buffer,
            last_queue_length: 0,
            flow_to_update_and_ingress_rate: HashMap::new(),
            flow_to_update_and_egress_rate: HashMap::new(),
            inner: Default::default(),
        }
    }

    fn should_drop(&mut self, p: &Pkt) -> bool {
        let occupancy = self.shadow_buffer.occupancy(p) as f64;
        let drop_prob = 1.0 - self.shadow_buffer.m_fair / occupancy;
        debug!("Time {}, Src: {:?}, MFair: {}, Occupancy: {}, drop prob: {}, queue length: {}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64(), p.ip_hdr.source, self.shadow_buffer.m_fair, occupancy, drop_prob, self.inner.len());
        rand::random::<f64>() < drop_prob
    }

    fn update_ingress_rate(&mut self, p: &Pkt) {
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

    fn update_egress_rate(&mut self, p: &Pkt) {
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

impl Scheduler for ApproximateFairDropping {

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
        let hwfq = super::ApproximateFairDropping::new(
            0.1
        );

        (
            hwfq,
            u32::to_be_bytes(all_ips[0]),
            u32::to_be_bytes(all_ips[1]),
            u32::to_be_bytes(all_ips[2]),
        )
    }

    #[test]
    fn afd_two_to_one() {
        init();
        let (mut hwfq, b_ip, c_ip, d_ip) = make_test_tree();
        let dst_ip = [42, 2, 0, 0];
        let mut b_cnt = 0;
        let mut c_cnt = 0;
        let mut d_cnt = 0;

        // Now enqueue a bunch but enqueue 2 b for every 1 c and 2 b for every 1 d.
        for _ in 0..10000 {
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

        fn is_diff(a: usize, b: usize) -> bool {
            ((a as isize) - (b as isize)).abs() > 5 && a as f64 / b as f64 > 1.1
        }
        dbg!(b_cnt, c_cnt, d_cnt);
        assert!(!is_diff(b_cnt, c_cnt));
        assert!(!is_diff(b_cnt, d_cnt));
        assert!(!is_diff(c_cnt, d_cnt));

        // Also ensure we sent more than 100 packets from each source.
        assert!(b_cnt > 100);
        assert!(c_cnt > 100);
        assert!(d_cnt > 100);
    }

#[test]
    fn afd_single_pair() {
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

        fn is_diff(a: usize, b: usize) -> bool {
            ((a as isize) - (b as isize)).abs() > 5 && a as f64 / b as f64 > 1.1
        }
        dbg!(b_cnt, c_cnt);
        assert!(!is_diff(b_cnt, c_cnt));

        // Also ensure we sent more than 100 packets from each source.
        assert!(b_cnt > 100);
        assert!(c_cnt > 100);
    }
}
