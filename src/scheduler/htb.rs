//! Classed pacer implementation.
//!
//! Pace in terms of absolute rates. Any excess parent rate is distributed to classes on a FIFO
//! basis.

use std::collections::VecDeque;

use color_eyre::eyre::{bail, ensure, Report};
use quanta::Instant;

use crate::Pkt;

use super::Scheduler;


#[derive(Debug)]
pub struct TokenBucket {
    rate_bytes_per_sec: usize,
    accum_bytes: usize,
    last_incr: Option<Instant>,
}

impl TokenBucket {
    pub fn new(rate_bytes_per_sec: usize) -> Self {
        Self {
            rate_bytes_per_sec,
            accum_bytes: 1514,
            last_incr: None,
        }
    }

    fn accumulate(&mut self) {
        let last_incr = match self.last_incr {
            Some(t) => t,
            None => {
                self.last_incr = Some(Instant::now());
                return;
            }
        };

        self.accum_bytes +=
            (last_incr.elapsed().as_secs_f64() * self.rate_bytes_per_sec as f64) as usize;
        self.last_incr = Some(Instant::now());
    }

    fn reset(&mut self) {
        self.last_incr = None;
        self.accum_bytes = 1514; // one packet
    }
}

#[derive(Debug)]
pub struct Class {
    pub dport: Option<u16>,
    common: TokenBucket,
    queue: VecDeque<Pkt>,
}

impl Class {
    pub fn new(dport: Option<u16>, tb: TokenBucket) -> Self {
        Self {
            dport,
            common: tb,
            queue: Default::default(),
        }
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn tot_len_bytes(&self) -> usize {
        self.queue.iter().map(|p| p.len()).sum()
    }

    fn tot_len_pkts(&self) -> usize {
        self.queue.len()
    }

    fn accumulate(&mut self) {
        if !self.queue.is_empty() {
            self.common.accumulate()
        }
    }

    fn try_deq(&mut self) -> Option<Pkt> {
        if let Some(p) = self.queue.front() {
            if p.len() < self.common.accum_bytes {
                self.common.accum_bytes -= p.len();
                self.queue.pop_front()
            } else {
                None
            }
        } else {
            // nothing in the queue. reset accum_bytes.
            self.common.reset();
            None
        }
    }

    fn deq(&mut self) -> Option<Pkt> {
        self.queue.pop_front()
    }
}

#[derive(Debug)]
pub struct ClassedTokenBucket {
    max_len_bytes: usize,
    classes: Vec<Class>,
    dport_to_idx: Vec<(u16, usize)>,
    curr_idx: usize,
}

impl ClassedTokenBucket {
    pub fn new(
        max_len_bytes: usize,
        classes: impl IntoIterator<Item = Class>,
        default_class: Option<Class>,
    ) -> Result<Self, Report> {
        if let Some(d) = &default_class {
            ensure!(d.dport.is_none(), "default class must not specify matchers");
        }

        let mut dport_to_idx = Vec::new();
        let mut cs: Vec<_> = default_class.into_iter().collect();
        for c in classes {
            if let Some(p) = c.dport {
                dport_to_idx.push((p, cs.len()));
                cs.push(c);
            } else {
                bail!("non-default class must specify matcher");
            }
        }

        Ok(Self {
            max_len_bytes,
            classes: cs,
            dport_to_idx,
            curr_idx: 0,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.classes.iter().all(Class::is_empty)
    }

    pub fn tot_len_bytes(&self) -> usize {
        self.classes.iter().map(Class::tot_len_bytes).sum()
    }

    pub fn tot_len_pkts(&self) -> usize {
        self.classes.iter().map(Class::tot_len_pkts).sum()
    }

    pub fn set_max_len_bytes(&mut self, bytes: usize) {
        self.max_len_bytes = bytes;
    }
}

impl Scheduler for ClassedTokenBucket {
    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        let tot_curr_len_bytes: usize = self.classes.iter().map(Class::tot_len_bytes).sum();
        ensure!(
            p.len() + tot_curr_len_bytes < self.max_len_bytes,
            "Dropping packet"
        );

        if let Some((_, i)) = self.dport_to_idx.iter().find(|&&(x, _)| x == p.dport) {
            self.classes[*i].queue.push_back(p);
        } else if self.classes[0].dport.is_none() {
            self.classes[0].queue.push_back(p);
        } else {
            bail!("Dropping packet");
        }

        Ok(())
    }

    fn deq(&mut self) -> Result<Option<Pkt>, Report> {
        // we don't have to handle pacing at the root, so if we can dequeue we should.

        // we should accumulate tokens for classes before dequeueing.
        // we need to use self.curr_idx *only* for going through bonus sending round-robin,
        // otherwise one queue will get all the bonus sends. here we're using it only as an
        // arbitrary start, and the real start index will be whichever class has the most
        // quanta.
        let mut start_idx = self.curr_idx;
        let mut curr_max = self.classes[start_idx].common.accum_bytes;
        for (i, c) in self.classes.iter_mut().enumerate() {
            if c.common.accum_bytes > curr_max {
                start_idx = i;
                curr_max = c.common.accum_bytes;
            }

            c.accumulate();
        }

        // first let's try to use classes' accumulated tokens.
        let stop_idx = start_idx;
        loop {
            if let Some(p) = self.classes[start_idx].try_deq() {
                return Ok(Some(p));
            }

            start_idx = (start_idx + 1) % self.classes.len();
            if start_idx == stop_idx {
                break;
            }
        }

        // no one had enough quanta to send within their guaranteed buckets. now we can try
        // borrowing from the parent. There's no need to pace, since deq() is already called with
        // some pacing), so any dequeue effectively borrows.
        let stop_idx = self.curr_idx;
        loop {
            if let Some(p) = self.classes[self.curr_idx].deq() {
                self.curr_idx = (self.curr_idx + 1) % self.classes.len();
                return Ok(Some(p));
            }

            self.curr_idx = (self.curr_idx + 1) % self.classes.len();
            if self.curr_idx == stop_idx {
                break;
            }
        }

        Ok(None)
    }
}

#[cfg(feature = "htb-argparse")]
pub mod parse_args {
    use std::str::FromStr;

    use clap::Parser;
    use color_eyre::eyre::{eyre, Report};

    use super::{Class, ClassedTokenBucket, TokenBucket};

    #[derive(Parser, Debug)]
    #[command(name = "hwfq")]
    pub struct Opt {
        #[arg(short, long)]
        pub queue_size_bytes: usize,

        #[arg(long)]
        pub class: Vec<ClassOpt>,

        #[arg(long)]
        pub default_class: Option<ClassOpt>,
    }

    impl FromStr for ClassedTokenBucket {
        type Err = Report;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let sp = s.split_whitespace();
            let dummy = std::iter::once("tmp");
            let opt = Opt::try_parse_from(dummy.chain(sp))?;
            opt.try_into()
        }
    }

    impl TryFrom<Opt> for ClassedTokenBucket {
        type Error = Report;
        fn try_from(o: Opt) -> Result<Self, Self::Error> {
            ClassedTokenBucket::new(
                o.queue_size_bytes,
                o.class.into_iter().map(Into::into),
                o.default_class.map(Into::into),
            )
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub struct ClassOpt {
        dport: u16,
        rate: usize,
    }

    impl FromStr for ClassOpt {
        type Err = Report;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let mut sp = s.split('=');
            let dport = sp
                .next()
                .ok_or_else(|| eyre!("dport=rate format for class"))?
                .parse()?;
            let rate = sp
                .next()
                .ok_or_else(|| eyre!("dport=rate format for class"))?
                .parse()?;
            Ok(ClassOpt { dport, rate })
        }
    }

    impl From<ClassOpt> for Class {
        fn from(c: ClassOpt) -> Class {
            if c.dport == 0 {
                Class::new(None, TokenBucket::new(c.rate))
            } else {
                Class::new(Some(c.dport), TokenBucket::new(c.rate))
            }
        }
    }

    #[cfg(test)]
    mod t {
        use crate::scheduler::htb::ClassedTokenBucket;

        #[test]
        fn parse_test() {
            let args = "--queue-size-bytes=120000 --class 4242=1000000 --class 4243=1000000";
            let sp: Vec<_> = args.split_whitespace().collect();
            dbg!(sp);
            let x: ClassedTokenBucket = args.parse().unwrap();
            assert_eq!(x.max_len_bytes, 120000);
            assert_eq!(x.classes[0].dport, Some(4242));
            assert_eq!(x.classes[0].common.rate_bytes_per_sec, 1000000);
            assert_eq!(x.classes[1].dport, Some(4243));
            assert_eq!(x.classes[1].common.rate_bytes_per_sec, 1000000);
        }
    }
}

#[cfg(test)]
mod t {
    use std::time::Duration;

    use quanta::Instant;

    use crate::scheduler::Scheduler;

    use super::{Class, ClassedTokenBucket, TokenBucket};

    fn enq_deq_packets(
        mut s: ClassedTokenBucket,
        mut overall: TokenBucket,
    ) -> (Duration, Vec<usize>) {
        // enqueue a bunch of 1KB dummy packets.
        let src_ip = [42, 2, 0, 0];
        let d_ip = [42, 1, 2, 6];

        let dports = [4242, 4243];
        for i in 0..600 {
            s.enq(crate::Pkt {
                ip_hdr: etherparse::Ipv4Header::new(
                    100,
                    64,
                    etherparse::IpNumber::TCP,
                    src_ip,
                    d_ip,
                )
                .unwrap(),
                dport: dports[i % dports.len()],
                buf: vec![],
                fake_len: 1500,
            })
            .expect("enqueue dummy packet");
        }

        let mut c1_cnt = 0;
        let mut c2_cnt = 0;
        let mut d_cnt = 0;

        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(1_000) {
            while overall.accum_bytes < 1500 {
                overall.accumulate();
                std::thread::sleep(Duration::from_millis(1));
            }

            let p = match s.deq().expect("dequeue") {
                None => {
                    dbg!("no more packets");
                    break;
                }
                Some(a) => a,
            };

            match p.dport {
                4242 => c1_cnt += p.len(),
                4243 => c2_cnt += p.len(),
                _ => d_cnt += p.len(),
            }

            overall.accum_bytes -= p.fake_len;
        }
        let el = start.elapsed();

        (el, vec![c1_cnt, c2_cnt, d_cnt])
    }

    #[test]
    fn backlog_fully_utilized() {
        const CLASS1_RATE: usize = 30_000;
        const CLASS2_RATE: usize = 70_000;

        let class1 = Class::new(Some(4242), TokenBucket::new(CLASS1_RATE));
        let class2 = Class::new(Some(4243), TokenBucket::new(CLASS2_RATE));
        let default_class = Class::new(None, TokenBucket::new(1_000));
        let s = ClassedTokenBucket::new(1_000_000, [class1, class2], Some(default_class)).unwrap();

        let overall = TokenBucket::new(100_000);
        let (el, v) = enq_deq_packets(s, overall);
        let c1_cnt = v[0];
        let c2_cnt = v[1];
        let d_cnt = v[2];

        let tot = c1_cnt + c2_cnt + d_cnt;
        dbg!(c1_cnt, c2_cnt, d_cnt, tot, el);

        // first, tot bytes / el sec should be close to 100_000 bytes / sec.
        let tot_tput = (tot as f64) / el.as_secs_f64();
        let tot_tput_err = ((tot_tput / 100_000.) - 1.).abs();
        assert!(
            tot_tput_err < 0.01,
            "total throughput error off by more than 1%"
        );

        // second, c2 / c1 should be close to 7 / 3 (since in this case guaranteed rates account
        // for the whole rate)
        assert!(
            ((c1_cnt as f64 / tot as f64) - (CLASS1_RATE as f64 / 100_000.)).abs() < 0.01,
            "class1 rate error off by more than 1%"
        );
        assert!(
            ((c2_cnt as f64 / tot as f64) - (CLASS2_RATE as f64 / 100_000.)).abs() < 0.01,
            "class2 rate error off by more than 1%"
        );
    }

    #[test]
    fn backlog_under_utilized() {
        const CLASS1_RATE: usize = 30_000;
        const CLASS2_RATE: usize = 30_000;

        let class1 = Class::new(Some(4242), TokenBucket::new(CLASS1_RATE));
        let class2 = Class::new(Some(4243), TokenBucket::new(CLASS2_RATE));
        let default_class = Class::new(None, TokenBucket::new(1_000));

        let s = ClassedTokenBucket::new(1_000_000, [class1, class2], Some(default_class)).unwrap();

        let overall = TokenBucket::new(100_000);
        let (el, v) = enq_deq_packets(s, overall);
        let c1_cnt = v[0];
        let c2_cnt = v[1];
        let d_cnt = v[2];
        let tot = c1_cnt + c2_cnt + d_cnt;
        dbg!(c1_cnt, c2_cnt, d_cnt, tot, el);

        // first, tot bytes / el sec should be close to 100_000 bytes / sec.
        let tot_tput = (tot as f64) / el.as_secs_f64();
        let tot_tput_err = ((tot_tput / 100_000.) - 1.).abs();
        assert!(
            tot_tput_err < 0.01,
            "total throughput error off by more than 1%"
        );

        // second, c2 / c1 should be close to 7 / 3 (since in this case guaranteed rates account
        // for the whole rate)
        assert!(
            ((c1_cnt as f64 / tot as f64) - (CLASS1_RATE as f64 / 100_000.)) > 0.01,
            "class1 rate error off by more than 1%"
        );
        assert!(
            ((c2_cnt as f64 / tot as f64) - (CLASS2_RATE as f64 / 100_000.)) > 0.01,
            "class2 rate error off by more than 1%"
        );
    }
}
