use super::Scheduler;
use crate::Pkt;
use color_eyre::eyre::Report;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::f64::consts::E;
use std::time::Duration;
use std::time::SystemTime;
use tracing::debug;
use tracing::error;

const MAX_PACKETS: usize = 500;

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

    pub fn num_unique_flows(&self) -> usize {
        let src_ips_seen = self
            .inner
            .iter()
            .map(|p| p.ip_hdr.source)
            .collect::<HashSet<[u8; 4]>>();
        src_ips_seen.len()
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
pub struct ApproximateFairDropping {
    shadow_buffer: ShadowBuffer,
    ingress_rate: f64,
    last_update_time: SystemTime,
    capacity: f64,
    last_capacity_update_time: SystemTime,
    inner: VecDeque<Pkt>,
}

impl ApproximateFairDropping {
    pub fn new(packet_sample_prob: f64) -> Self {
        let shadow_buffer = ShadowBuffer::new(packet_sample_prob, MAX_PACKETS);

        Self {
            shadow_buffer,
            ingress_rate: 0.0,
            last_update_time: SystemTime::now(),
            capacity: 0.0,
            last_capacity_update_time: SystemTime::now(),
            inner: Default::default(),
        }
    }

    fn should_drop(&mut self, p: &Pkt) -> bool {
        let occupancy = self.shadow_buffer.occupancy(p) as f64;
        let b = self.shadow_buffer.size() as f64;
        let n = self.shadow_buffer.num_unique_flows() as f64;
        let drop_prob = 1.0 - (b / (n * occupancy)) * self.capacity / self.ingress_rate;
        // debug!("IP {:?}",
        //     p.ip_hdr.source
        // );
        // debug!("  occupancy: {}", occupancy);
        // debug!("  b: {}", b);
        // debug!("  n: {}", n);
        // debug!("  drop_prob: {}", drop_prob);
        rand::random::<f64>() < drop_prob
    }

    fn update_ingress_rate(&mut self, p: &Pkt) {
        let time_since_rate_calc = self.last_update_time.elapsed().unwrap().as_secs_f64();
        let new_rate = p.len() as f64 / time_since_rate_calc;
        self.ingress_rate =
            exponential_smooth(self.ingress_rate, new_rate, time_since_rate_calc, K);
        self.last_update_time = SystemTime::now();
    }

    fn update_capacity(&mut self, p: &Pkt) {
        let time_since_rate_calc = self
            .last_capacity_update_time
            .elapsed()
            .unwrap()
            .as_secs_f64();
        let new_rate = p.len() as f64 / time_since_rate_calc;
        self.capacity = exponential_smooth(self.capacity, new_rate, time_since_rate_calc, K);
        self.last_capacity_update_time = SystemTime::now();
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

    fn len_bytes(&self) -> usize {
        self.inner.iter().map(Pkt::len).sum()
    }

    fn len_packets(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn set_max_len_bytes(&mut self, _bytes: usize) -> Result<(), Report> {
        // not implemented
        Ok(())
    }

    fn dbg(&mut self, epoch_dur: Duration) {
        self.shadow_buffer.dbg();
        debug!(?epoch_dur, ?self.inner, "afd");
    }
}

#[cfg(test)]
pub(crate) mod t {
    use crate::Scheduler;

    fn init() {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            tracing_subscriber::fmt::init();
            color_eyre::install().unwrap();
        })
    }

    fn make_test_tree() -> (super::ApproximateFairDropping, [u8; 4], [u8; 4], [u8; 4]) {
        let all_ips = [
            u32::from_be_bytes([42, 0, 0, 0]),
            u32::from_be_bytes([42, 1, 1, 1]),
            u32::from_be_bytes([42, 1, 2, 1]),
        ];
        let hwfq = super::ApproximateFairDropping::new(0.1);

        (
            hwfq,
            u32::to_be_bytes(all_ips[0]),
            u32::to_be_bytes(all_ips[1]),
            u32::to_be_bytes(all_ips[2]),
        )
    }

    pub fn enq_rate<S: Scheduler>(
        hwfq: &mut S,
        dst_ip: [u8; 4],
        flows: impl IntoIterator<Item = ([u8; 4], usize)>,
    ) {
        for (ip, ingress_rate) in flows {
            for _ in 0..ingress_rate {
                hwfq.enq(crate::test_util::make_pkt(ip, dst_ip, None, None, 100))
                    .unwrap();
            }
        }
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
            enq_rate(&mut hwfq, dst_ip, [(b_ip, 2), (c_ip, 1), (d_ip, 1)]);

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
                    Ok(None) => {}
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
        let (mut hwfq, b_ip, c_ip, _d_ip) = make_test_tree();
        let dst_ip = [42, 2, 0, 0];
        let mut b_cnt = 0;
        let mut c_cnt = 0;

        // Now enqueue a bunch but enqueue 8 b for every 1 c.
        for _ in 0..10000 {
            enq_rate(&mut hwfq, dst_ip, [(b_ip, 8), (c_ip, 1)]);

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
                    Ok(None) => {}
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
