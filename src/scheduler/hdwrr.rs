use super::Scheduler;
use crate::scheduler::weight_tree::WeightTree;
use crate::scheduler::weight_tree::MAX_NUM_CHILDREN;
use crate::Error;
use crate::Pkt;
use color_eyre::eyre::{ensure, Report};
#[cfg(feature = "hwfq-audit")]
use std::collections::HashMap;
use std::collections::VecDeque;
use std::time::Duration;
use tracing::debug;

/// Implement a hierarchical deficit round-robin [`Scheduler`].
///
/// See [`HierarchicalDeficitWeightedRoundRobin::new`].
#[derive(Debug)]
pub struct HierarchicalDeficitWeightedRoundRobin {
    limit_bytes: usize,
    lookup_on_src_ip: bool,
    tree: FlowTree,
}

impl HierarchicalDeficitWeightedRoundRobin {
    /// Construct a HDWRR scheduler.
    ///
    /// # Arguments
    /// - `limit_bytes`: The *total size* of the queue.
    /// - `lookup_on_src_ip`: Whether to use the source or destination IP address to match on the
    /// weight tree. Using the source IP address (`true`) will schedule based on sender weights,
    /// and using the destination IP address (`false`) will use receiver weights.
    /// - `weight_tree`: The weight tree to classify packets with. See [`WeightTree`].
    pub fn new(
        limit_bytes: usize,
        lookup_on_src_ip: bool,
        weight_tree: WeightTree,
    ) -> Result<Self, Report> {
        Ok(Self {
            limit_bytes,
            lookup_on_src_ip,
            tree: weight_tree.into_flow_tree()?,
        })
    }
}

impl Scheduler for HierarchicalDeficitWeightedRoundRobin {
    fn enq(&mut self, p: Pkt) -> Result<(), Report> {
        let pkt_len = p.len();
        ensure!(
            self.tree.tot_qlen() + pkt_len <= self.limit_bytes,
            Error::PacketDropped(p)
        );

        if self.lookup_on_src_ip {
            self.tree.enqueue::<true>(p);
        } else {
            self.tree.enqueue::<false>(p);
        }
        Ok(())
    }

    fn deq(&mut self) -> Result<Option<Pkt>, Report> {
        if self.tree.tot_qlen() == 0 {
            return Ok(None);
        }

        // we know there is something to dequeue.
        // so we must continue adding deficit until something dequeues.
        loop {
            if let Some(p) = self.tree.dequeue() {
                return Ok(Some(p));
            }

            self.tree.add_deficit(self.tree.quanta());
        }
    }

    fn len_bytes(&self) -> usize {
        self.tree.tot_qlen()
    }

    fn len_packets(&self) -> usize {
        self.tree.tot_pkts()
    }

    fn set_max_len_bytes(&mut self, bytes: usize) -> Result<(), Report> {
        self.limit_bytes = bytes;
        Ok(())
    }

    fn dbg(&mut self, epoch_dur: Duration) {
        tracing::info!(?epoch_dur, ?self.tree, "hdwrr tree state");
    }
}

enum FlowTree {
    Leaf {
        deficit: usize,
        quanta: usize,
        curr_qlen: usize,
        queue: VecDeque<Pkt>,
    },
    NonLeaf {
        // a list of ips to classify enqueues into children. if classify[i].contains( { src_ip or dst_ip }), we
        // enq into children[i].
        classify: [Vec<u32>; MAX_NUM_CHILDREN],

        deficit: usize,
        quanta: usize,
        curr_qlen: usize,

        curr_child: usize,
        // in theory the child list could be bigger (linked list), but meh, we are not going to test any topologies with
        // tree width > 4.
        children: [Box<FlowTree>; MAX_NUM_CHILDREN],
        children_remaining_quanta: [usize; MAX_NUM_CHILDREN],

        // bytes dequeued when the given configuration of non-empty queues was active.
        #[cfg(feature = "hwfq-audit")]
        curr_audit_state: [bool; MAX_NUM_CHILDREN],
        #[cfg(feature = "hwfq-audit")]
        audit_tracking: HashMap<[bool; MAX_NUM_CHILDREN], [usize; MAX_NUM_CHILDREN]>,
    },
}

impl std::fmt::Debug for FlowTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match *self {
            FlowTree::Leaf {
                quanta, ref queue, ..
            } => f
                .debug_struct("FlowTree::Leaf")
                .field("quanta", &quanta)
                .field("queue_len", &queue.len())
                .finish_non_exhaustive(),

            FlowTree::NonLeaf {
                quanta,
                ref classify,
                ref children,
                #[cfg(feature = "hwfq-audit")]
                ref audit_tracking,
                ..
            } => {
                let mut s = f.debug_struct("FlowTree::NonLeaf");
                s.field("quanta", &quanta);
                #[cfg(feature = "hwfq-audit")]
                s.field("audit_tracking", audit_tracking);
                s.field("child0", &(&classify[0], &children[0]));

                for i in 1..=3 {
                    if !classify[i].is_empty() {
                        s.field("child", &(&classify[i], &children[i]));
                    }
                }

                s.finish()
            }
        }
    }
}

impl FlowTree {
    fn tot_qlen(&self) -> usize {
        match self {
            &FlowTree::NonLeaf { curr_qlen, .. } | &FlowTree::Leaf { curr_qlen, .. } => curr_qlen,
        }
    }

    fn tot_pkts(&self) -> usize {
        match self {
            FlowTree::Leaf { queue, .. } => queue.len(),
            FlowTree::NonLeaf { children, .. } => children.iter().map(|t| t.tot_pkts()).sum(),
        }
    }

    fn enqueue<const USE_SRC_IP: bool>(&mut self, p: Pkt) {
        match *self {
            FlowTree::Leaf {
                ref mut queue,
                ref mut curr_qlen,
                ..
            } => {
                *curr_qlen += p.len();
                queue.push_back(p);
            }
            FlowTree::NonLeaf {
                ref mut children,
                ref mut classify,
                ref mut curr_qlen,
                #[cfg(feature = "hwfq-audit")]
                ref mut curr_audit_state,
                #[cfg(feature = "hwfq-audit")]
                ref mut audit_tracking,
                ..
            } => {
                for i in 0..children.len() {
                    if classify[i].is_empty() {
                        continue;
                    }

                    let ip = if USE_SRC_IP {
                        u32::from_be_bytes(p.ip_hdr.source)
                    } else {
                        u32::from_be_bytes(p.ip_hdr.destination)
                    };

                    if classify[i].iter().any(|i| ip == *i) {
                        *curr_qlen += p.len();

                        #[cfg(feature = "hwfq-audit")]
                        if !curr_audit_state[i] && children[i].tot_qlen() == 0 {
                            curr_audit_state[i] = true;
                            if !audit_tracking.contains_key(curr_audit_state) {
                                audit_tracking
                                    .insert(*curr_audit_state, [0usize; MAX_NUM_CHILDREN]);
                            }
                        }

                        children[i].enqueue::<USE_SRC_IP>(p);
                        return;
                    }
                }

                debug!(ip_hdr = ?p.ip_hdr, "Packet did not match any classifications");
            }
        }
    }

    fn quanta(&self) -> usize {
        match self {
            &FlowTree::NonLeaf { quanta, .. } | &FlowTree::Leaf { quanta, .. } => quanta,
        }
    }

    fn add_deficit(&mut self, q: usize) {
        match self {
            &mut FlowTree::NonLeaf {
                ref mut deficit, ..
            }
            | &mut FlowTree::Leaf {
                ref mut deficit, ..
            } => *deficit += q,
        }
    }

    fn dequeue(&mut self) -> Option<Pkt> {
        match *self {
            FlowTree::Leaf {
                ref mut deficit,
                ref mut curr_qlen,
                ref mut queue,
                ..
            } => {
                if !queue.is_empty() && *deficit >= queue.front().unwrap().len() {
                    let p = queue.pop_front().unwrap();
                    if queue.is_empty() {
                        *deficit = 0;
                        *curr_qlen = 0;
                    } else {
                        *deficit -= p.len();
                        *curr_qlen -= p.len();
                    }

                    return Some(p);
                }

                None
            }
            FlowTree::NonLeaf {
                ref mut deficit,
                ref mut curr_qlen,
                ref mut curr_child,
                ref mut children_remaining_quanta,
                ref mut children,
                #[cfg(feature = "hwfq-audit")]
                ref mut curr_audit_state,
                #[cfg(feature = "hwfq-audit")]
                ref mut audit_tracking,
                ..
            } => {
                if *curr_qlen == 0 {
                    return None;
                }

                loop {
                    if children[*curr_child].tot_qlen() > 0 {
                        // is our sub-leaf currently dequeueing packets that fit within credits we already gave it?
                        if let Some(p) = children[*curr_child].dequeue() {
                            *curr_qlen -= p.buf.len();

                            #[cfg(feature = "hwfq-audit")]
                            {
                                let curr_state: &mut [usize; MAX_NUM_CHILDREN] =
                                    audit_tracking.get_mut(curr_audit_state).unwrap();
                                curr_state[*curr_child] += p.buf.len();

                                if children[*curr_child].tot_qlen() == 0 {
                                    assert!(curr_audit_state[*curr_child], "queue audit tracking is off: child was inactive when it should have been active.");
                                    curr_audit_state[*curr_child] = false;
                                }
                            }

                            return Some(p);
                        }

                        // the child doesn't have enough deficit.
                        if *deficit > 0 {
                            // how much of our current deficit should we give? it is min(our
                            // current deficit, child's quanta). our current deficit because we
                            // cannot give more than we have, and child's quanta because that is
                            // how the weights happen.
                            let ask = children[*curr_child].quanta()
                                + children_remaining_quanta[*curr_child];
                            let q = std::cmp::min(*deficit, ask);

                            if q == *deficit {
                                children_remaining_quanta[*curr_child] = ask - q;
                            } else {
                                children_remaining_quanta[*curr_child] = 0;
                            }

                            *deficit -= q;
                            children[*curr_child].add_deficit(q);
                        } else {
                            // we don't have any deficit to give. ask for more.
                            return None;
                        }
                    }

                    *curr_child = (*curr_child + 1) % children.len();
                }
            }
        }
    }
}

impl WeightTree {
    // transform this weight tree with weights into a flow tree with quanta.
    // this allocates quanta to children satisfying the following:
    // quantum = sum(child.quantum / child.weight)
    fn into_flow_tree(self) -> Result<FlowTree, Report> {
        let mut min_quantum = self.get_min_quantum()?;
        if min_quantum < 500 {
            min_quantum *= 500 / min_quantum;
        }

        self.into_flow_tree_with_quantum(min_quantum)
    }

    fn into_flow_tree_with_quantum(self, quantum: usize) -> Result<FlowTree, Report> {
        Ok(match self {
            WeightTree::Leaf { .. } => FlowTree::Leaf {
                quanta: quantum,
                deficit: 0,
                curr_qlen: 0,
                queue: Default::default(),
            },
            WeightTree::NonLeaf {
                ips, mut children, ..
            } => {
                let sum_weights: usize = children
                    .iter()
                    .filter_map(|c| c.as_ref())
                    .map(|c| c.weight())
                    .sum();
                ensure!(sum_weights > 0, "no children for non-leaf node");

                let process_child = |c: Box<WeightTree>, slot: &mut Box<FlowTree>| {
                    let wt = c.weight();
                    // it is important that we multiply first before dividing by sum_weights,
                    // since sum_weights might not be a divisor of quantum.
                    let child_quantum = (wt * quantum) / sum_weights;

                    let ft = c.into_flow_tree_with_quantum(child_quantum)?;
                    let slot_ref = slot.as_mut();
                    *slot_ref = ft;
                    Ok::<_, Report>(())
                };

                let mut flow_children = [(); MAX_NUM_CHILDREN].map(|_| {
                    Box::new(FlowTree::Leaf {
                        quanta: 0,
                        deficit: 0,
                        curr_qlen: 0,
                        queue: Default::default(),
                    })
                });
                for i in 0..MAX_NUM_CHILDREN {
                    if let Some(c) = children[i].take() {
                        process_child(c, &mut flow_children[i])?;
                    }
                }

                FlowTree::NonLeaf {
                    quanta: quantum,
                    classify: ips,
                    deficit: 0,
                    curr_qlen: 0,
                    curr_child: 0,
                    children: flow_children,
                    children_remaining_quanta: [0usize; MAX_NUM_CHILDREN],
                    #[cfg(feature = "hwfq-audit")]
                    curr_audit_state: Default::default(),
                    #[cfg(feature = "hwfq-audit")]
                    audit_tracking: Default::default(),
                }
            }
        })
    }
}

#[cfg(test)]
mod t {
    use super::{Scheduler, WeightTree};
    use crate::scheduler::weight_tree::parse_ip;
    use crate::Pkt;
    use tracing::info;

    fn init() {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            tracing_subscriber::fmt::init();
            color_eyre::install().unwrap();
        })
    }

    #[test]
    fn weight_tree() {
        init();
        let wt = WeightTree::parent(1)
            .add_child(vec![u32::from_be_bytes([42, 1, 0, 3])], WeightTree::leaf(1))
            .unwrap()
            .add_child(
                vec![u32::from_be_bytes([42, 1, 1, 15])],
                WeightTree::leaf(2),
            )
            .unwrap();
        dbg!(&wt);

        let ft = wt.into_flow_tree().unwrap();
        dbg!(ft);

        let _wt = WeightTree::parent(1)
            .add_child(vec![u32::from_be_bytes([42, 1, 0, 5])], WeightTree::leaf(1))
            .unwrap()
            .add_child(
                vec![u32::from_be_bytes([42, 1, 1, 9])],
                WeightTree::parent(2),
            )
            .unwrap_err();
    }

    #[test]
    fn bad_weight_tree() {
        init();
        let _wt = WeightTree::parent(1)
            .add_child(vec![], WeightTree::leaf(1))
            .unwrap()
            .add_child(
                vec![],
                WeightTree::parent(2)
                    .add_child(vec![0x1], WeightTree::leaf(1)) // "D"
                    .unwrap()
                    .add_child(vec![0x2], WeightTree::leaf(2)) // "E"
                    .unwrap(),
            )
            .unwrap_err();
    }

    fn make_test_tree() -> (
        super::HierarchicalDeficitWeightedRoundRobin,
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
        dbg!(wt.clone().into_flow_tree().unwrap());
        let hwfq = super::HierarchicalDeficitWeightedRoundRobin::new(
            150_000, /* 100 x 1500 bytes */
            true, wt,
        )
        .unwrap();

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

        assert_eq!(hwfq.tree.tot_qlen(), 0, "");
        assert_eq!(hwfq.tree.tot_pkts(), 0, "");
        // enqueue a bunch of packets
        for _ in 0..100 {
            hwfq.enq(Pkt {
                ip_hdr: etherparse::Ipv4Header::new(
                    100,
                    64,
                    etherparse::IpNumber::TCP,
                    b_ip,
                    dst_ip,
                )
                .unwrap(),
                dport: 0,
                buf: vec![],
                fake_len: 100,
            })
            .unwrap();
            hwfq.enq(Pkt {
                ip_hdr: etherparse::Ipv4Header::new(
                    100,
                    64,
                    etherparse::IpNumber::TCP,
                    d_ip,
                    dst_ip,
                )
                .unwrap(),
                dport: 0,
                buf: vec![],
                fake_len: 100,
            })
            .unwrap();
            hwfq.enq(Pkt {
                ip_hdr: etherparse::Ipv4Header::new(
                    100,
                    64,
                    etherparse::IpNumber::TCP,
                    e_ip,
                    dst_ip,
                )
                .unwrap(),
                dport: 0,
                buf: vec![],
                fake_len: 100,
            })
            .unwrap();
        }

        assert_eq!(hwfq.tree.tot_pkts(), 300, "");
        assert_eq!(hwfq.tree.tot_qlen(), 300 * 100, "");

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

        info!(?hwfq.tree, "tree");
    }

    #[test]
    fn hwfq_partially_active() {
        init();
        let (mut hwfq, b_ip, d_ip, e_ip) = make_test_tree();
        let dst_ip = [42, 2, 0, 0];

        assert_eq!(hwfq.tree.tot_qlen(), 0, "");
        // enqueue only d and e packets
        for _ in 0..60 {
            hwfq.enq(Pkt {
                ip_hdr: etherparse::Ipv4Header::new(
                    100,
                    64,
                    etherparse::IpNumber::TCP,
                    d_ip,
                    dst_ip,
                )
                .unwrap(),
                dport: 0,
                buf: vec![],
                fake_len: 100,
            })
            .unwrap();
            hwfq.enq(Pkt {
                ip_hdr: etherparse::Ipv4Header::new(
                    100,
                    64,
                    etherparse::IpNumber::TCP,
                    e_ip,
                    dst_ip,
                )
                .unwrap(),
                dport: 0,
                buf: vec![],
                fake_len: 100,
            })
            .unwrap();
        }

        assert_eq!(hwfq.tree.tot_qlen(), 120 * 100, "");

        let mut b_cnt = 0;
        let mut d_cnt = 0;
        let mut e_cnt = 0;
        for _ in 0..60 {
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

        assert_eq!(b_cnt, 0, "should not get b packets");

        // should be e ~= 2 * d
        dbg!(d_cnt, e_cnt);
        let e = e_cnt as isize;
        let twice_d = (d_cnt * 2) as isize;
        assert!((twice_d - e).abs() < 10);
    }

    #[test]
    fn parse_ip_test() {
        init();

        let p = "42.1.2.15";
        let m = parse_ip(p).unwrap();
        assert_eq!(m, u32::from_be_bytes([42, 1, 2, 15]));

        let p = "1.1.1.1";
        let m = parse_ip(p).unwrap();
        assert_eq!(m, u32::from_be_bytes([1, 1, 1, 1]));
    }

    #[test]
    fn parse_yaml() {
        init();
        let cfg_str = "\
root:
  - h0:
    ips: [\"42.0.0.0\"]
    weight: 1
  - h1:
    ips: [\"42.1.3.0\", \"42.1.4.0\"]
    weight: 2
    children:
      - h3:
        ips: [\"42.1.3.0\"]
        weight: 1
      - h4:
        ips: [\"42.1.4.0\"]
        weight: 2
        ";

        let wt = WeightTree::from_cfg(cfg_str).unwrap();
        dbg!(&wt);
        assert!(
            matches!(
                wt,
                WeightTree::NonLeaf {
                    weight: 1,
                    children: [
                        Some(l1 ),
                        Some(l2 ),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ],
                    ..
                } if matches!(&*l1, &WeightTree::Leaf { weight: 1, ..}) &&
                     matches!(&*l2, &WeightTree::NonLeaf {
                            weight: 2,
                            children: [
                                Some(ref l3 ),
                                Some(ref l4 ),
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                            ],
                            ..
                    } if matches!(&**l3, WeightTree::Leaf { weight: 1, ..}) &&
                         matches!(&**l4, WeightTree::Leaf { weight: 2, ..})
                    )
            ),
            "wrong weighttree"
        );
    }

    #[test]
    fn receive_hwfq() {
        init();
        let dst_ips = [[42, 0, 0, 9], [42, 1, 1, 3], [42, 1, 2, 6]];

        let wt = WeightTree::parent(1)
            .add_child(vec![u32::from_be_bytes(dst_ips[0])], WeightTree::leaf(1)) // "B"
            .unwrap()
            .add_child(
                vec![
                    u32::from_be_bytes(dst_ips[1]),
                    u32::from_be_bytes(dst_ips[2]),
                ],
                WeightTree::parent(2)
                    .add_child(vec![u32::from_be_bytes(dst_ips[1])], WeightTree::leaf(1)) // "D"
                    .unwrap()
                    .add_child(vec![u32::from_be_bytes(dst_ips[2])], WeightTree::leaf(2)) // "E"
                    .unwrap(),
            )
            .unwrap();

        let mut hwfq = super::HierarchicalDeficitWeightedRoundRobin::new(
            150_000, /* 100 x 1500 bytes */
            false, wt,
        )
        .unwrap();

        let b_ip = dst_ips[0];
        let d_ip = dst_ips[1];
        let e_ip = dst_ips[2];
        let src_ip = [42, 2, 0, 0];

        assert_eq!(hwfq.tree.tot_qlen(), 0, "");
        // enqueue a bunch of packets
        for _ in 0..100 {
            hwfq.enq(Pkt {
                ip_hdr: etherparse::Ipv4Header::new(
                    100,
                    64,
                    etherparse::IpNumber::TCP,
                    src_ip,
                    b_ip,
                )
                .unwrap(),
                dport: 0,
                buf: vec![],
                fake_len: 100,
            })
            .unwrap();
            hwfq.enq(Pkt {
                ip_hdr: etherparse::Ipv4Header::new(
                    100,
                    64,
                    etherparse::IpNumber::TCP,
                    src_ip,
                    d_ip,
                )
                .unwrap(),
                dport: 0,
                buf: vec![],
                fake_len: 100,
            })
            .unwrap();
            hwfq.enq(Pkt {
                ip_hdr: etherparse::Ipv4Header::new(
                    100,
                    64,
                    etherparse::IpNumber::TCP,
                    src_ip,
                    e_ip,
                )
                .unwrap(),
                dport: 0,
                buf: vec![],
                fake_len: 100,
            })
            .unwrap();
        }

        assert_eq!(hwfq.tree.tot_qlen(), 300 * 100, "");

        let mut b_cnt = 0;
        let mut d_cnt = 0;
        let mut e_cnt = 0;
        for _ in 0..180 {
            let p = hwfq.deq().unwrap().unwrap();
            if p.ip_hdr.destination == b_ip {
                b_cnt += 1;
            } else if p.ip_hdr.destination == d_ip {
                d_cnt += 1;
            } else if p.ip_hdr.destination == e_ip {
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
