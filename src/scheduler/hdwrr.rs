use super::Scheduler;
use crate::Pkt;
use color_eyre::eyre::{bail, ensure, eyre, Report, WrapErr};
use std::collections::VecDeque;
use tracing::debug;

pub struct HierarchicalDeficitWeightedRoundRobin {
    limit_bytes: usize,
    lookup_on_src_ip: bool,
    tree: FlowTree,
}

impl HierarchicalDeficitWeightedRoundRobin {
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
        let pkt_len = p.buf.len();
        ensure!(
            self.tree.tot_qlen() + pkt_len <= self.limit_bytes,
            "Dropping packet"
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
}

pub enum FlowTree {
    Leaf {
        deficit: usize,
        quanta: usize,
        curr_qlen: usize,
        queue: VecDeque<Pkt>,
    },
    NonLeaf {
        // a list of ips to classify enqueues into children. if classify[i].contains( { src_ip or dst_ip }), we
        // enq into children[i].
        classify: [Vec<u32>; 4],

        deficit: usize,
        quanta: usize,
        curr_qlen: usize,

        curr_child: usize,
        // in theory the child list could be bigger (linked list), but meh, we are not going to test any topologies with
        // tree width > 4.
        children: [Box<FlowTree>; 4],
        children_remaining_quanta: [usize; 4],
    },
}

impl std::fmt::Debug for FlowTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            &FlowTree::Leaf {
                quanta, ref queue, ..
            } => f
                .debug_struct("FlowTree::Leaf")
                .field("quanta", &quanta)
                .field("queue_len", &queue.len())
                .finish_non_exhaustive(),

            &FlowTree::NonLeaf {
                quanta,
                ref classify,
                ref children,
                ..
            } => {
                let mut s = f.debug_struct("FlowTree::NonLeaf");
                s.field("quanta", &quanta)
                    .field("child0", &(&classify[0], &children[0]));

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

    fn enqueue<const USE_SRC_IP: bool>(&mut self, p: Pkt) {
        match self {
            &mut FlowTree::Leaf {
                ref mut queue,
                ref mut curr_qlen,
                ..
            } => {
                *curr_qlen += p.buf.len();
                queue.push_back(p);
            }
            &mut FlowTree::NonLeaf {
                ref mut children,
                ref mut classify,
                ref mut curr_qlen,
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
                        *curr_qlen += p.buf.len();
                        children[i].enqueue::<USE_SRC_IP>(p);
                        return;
                    }
                }

                debug!(ip_hdr = ?p.ip_hdr, "Packet did not match any classifications");
                return;
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
        match self {
            &mut FlowTree::Leaf {
                ref mut deficit,
                ref mut curr_qlen,
                ref mut queue,
                ..
            } => {
                if !queue.is_empty() {
                    if *deficit >= queue.front().unwrap().buf.len() {
                        let p = queue.pop_front().unwrap();
                        if queue.is_empty() {
                            *deficit = 0;
                            *curr_qlen = 0;
                        } else {
                            *deficit -= p.buf.len();
                            *curr_qlen -= p.buf.len();
                        }

                        return Some(p);
                    }
                }

                None
            }
            &mut FlowTree::NonLeaf {
                ref mut deficit,
                ref mut curr_qlen,
                ref mut curr_child,
                ref mut children_remaining_quanta,
                ref mut children,
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

const MAX_NUM_CHILDREN: usize = 4;

#[derive(Clone, Debug)]
pub enum WeightTree {
    Leaf {
        weight: usize,
    },
    NonLeaf {
        weight: usize,
        ips: [Vec<u32>; MAX_NUM_CHILDREN],
        children: [Option<Box<WeightTree>>; MAX_NUM_CHILDREN],
    },
}

fn parse_ip(ip: &str) -> Result<u32, Report> {
    let ip: Vec<_> = ip.split('.').collect();
    ensure!(ip.len() == 4, "ip must be a.b.c.d");
    let (a, b, c, d) = match &ip[..] {
        &[a, b, c, d] => (a.parse()?, b.parse()?, c.parse()?, d.parse()?),
        _ => unreachable!(),
    };

    let ip = u32::from_be_bytes([a, b, c, d]);
    Ok(ip)
}

use yaml_rust::Yaml;
fn from_yaml(yaml: Yaml) -> Result<(Vec<u32>, WeightTree), Report> {
    let mut node = yaml
        .into_hash()
        .ok_or_else(|| eyre!("Node must be dictionary"))?;
    let ips = node
        .remove(&Yaml::String("ips".to_owned()))
        .ok_or_else(|| eyre!("Need ips key"))?
        .into_vec()
        .ok_or_else(|| eyre!("ips must be string array"))?
        .into_iter()
        .map(|ip_yaml| {
            let ip_str = ip_yaml
                .into_string()
                .ok_or_else(|| eyre!("ip must be a string"))?;
            parse_ip(&ip_str)
        })
        .collect::<Result<_, Report>>()?;
    let weight = node
        .remove(&Yaml::String("weight".to_owned()))
        .ok_or_else(|| eyre!("Need weight key"))?
        .into_i64()
        .ok_or_else(|| eyre!("Weight must be uint"))? as usize;

    if let Some(children) = node.remove(&Yaml::String("children".to_owned())) {
        Ok((
            ips,
            children
                .into_iter()
                .try_fold(WeightTree::parent(weight), |parent, child| {
                    let (ips, child_node) = from_yaml(child)?;
                    parent.add_child(ips, child_node)
                })?,
        ))
    } else {
        Ok((ips, WeightTree::leaf(weight)))
    }
}

impl WeightTree {
    /// Load `WeightTree` from yaml config file.
    ///
    /// # Example
    /// ```yaml
    /// root:
    ///   - h0:
    ///     ips: ["10.10.0.1"]
    ///     weight: 1
    ///   - h1:
    ///     ips: ["13.0.2.3","19.0.1.2"]
    ///     weight: 2
    ///     children:
    ///       - h3:
    ///         ips: ["13.0.2.3"]
    ///         weight: 1
    ///       - h4:
    ///         ips: ["19.0.1.2"]
    ///         weight: 2
    /// ```
    pub fn from_file(file: impl AsRef<std::path::Path>) -> Result<Self, Report> {
        let cfg_str = std::fs::read_to_string(file.as_ref())
            .wrap_err(eyre!("Could not read {:?}", file.as_ref()))?;
        Self::from_str(&cfg_str)
    }

    pub fn from_str(cfg: &str) -> Result<Self, Report> {
        let yaml =
            yaml_rust::YamlLoader::load_from_str(cfg).wrap_err(eyre!("Error reading {:?}", cfg))?;
        ensure!(yaml.len() == 1, "Tree cfg needs exactly one element");
        let children = yaml
            .into_iter()
            .next()
            .unwrap()
            .into_hash()
            .ok_or_else(|| eyre!("Need dictionary structure"))?
            .remove(&Yaml::String("root".to_owned()))
            .ok_or_else(|| eyre!("Toplevel key must be `root`"))?
            .into_vec()
            .ok_or_else(|| eyre!("Toplevel value must be list of child nodes"))?;

        children
            .into_iter()
            .try_fold(Self::parent(1), |parent, child| {
                let (ips, child_node) = from_yaml(child)?;
                parent.add_child(ips, child_node)
            })
    }

    pub fn leaf(weight: usize) -> Self {
        WeightTree::Leaf { weight }
    }

    pub fn parent(weight: usize) -> Self {
        const INIT_VEC: Vec<u32> = Vec::new();
        WeightTree::NonLeaf {
            weight,
            ips: [INIT_VEC; 4],
            children: [None, None, None, None],
        }
    }

    fn check_and_collect_ips(&self) -> Result<Vec<u32>, Report> {
        match &self {
            WeightTree::Leaf { .. } => Ok(Vec::new()),
            WeightTree::NonLeaf { ips, children, .. } => {
                let mut node_ips = Vec::new();
                for c in 0..MAX_NUM_CHILDREN {
                    if let Some(ref child) = children[c] {
                        match child.as_ref() {
                            WeightTree::Leaf { .. } => {
                                node_ips.extend(ips[c].clone());
                            }
                            WeightTree::NonLeaf { .. } => {
                                let child_ips = child.check_and_collect_ips()?;
                                ensure!(
                                    child_ips == ips[c],
                                    "Node IP list mismatched children: {:?}",
                                    self
                                );
                                node_ips.extend(child_ips);
                            }
                        }
                    }
                }

                node_ips.sort();
                Ok(node_ips)
            }
        }
    }

    pub fn add_child(mut self, mut child_ips: Vec<u32>, child: Self) -> Result<Self, Report> {
        if let WeightTree::NonLeaf { .. } = &child {
            child_ips.sort();
            let collected_child_ips = child.check_and_collect_ips()?;
            ensure!(
                child_ips == collected_child_ips,
                "Mismatched ips with ips present in child tree: {:?} != {:?}, {:?}",
                child_ips,
                collected_child_ips,
                child
            );
        }

        match &mut self {
            WeightTree::Leaf { .. } => bail!("Cannot add child to leaf"),
            &mut WeightTree::NonLeaf {
                ref mut ips,
                ref mut children,
                ..
            } => {
                for c in 0..MAX_NUM_CHILDREN {
                    if ips[c].is_empty() {
                        ips[c] = child_ips;
                        children[c] = Some(Box::new(child));
                        break;
                    }
                }

                Ok(self)
            }
        }
    }

    fn get_min_quantum(&self) -> Result<usize, Report> {
        match self {
            WeightTree::Leaf { weight } => Ok(*weight),
            WeightTree::NonLeaf { children, .. } => {
                let (children_min_quanta, children_weights): (Vec<_>, Vec<_>) = children
                    .iter()
                    .filter_map(|c| c.as_ref())
                    .map(|c| (c.get_min_quantum(), c.weight()))
                    .unzip();
                let weight_sum: usize = children_weights.into_iter().sum();
                ensure!(weight_sum > 0, "NonLeaf node must have children");
                let children_min_quanta_ok: Result<Vec<_>, _> =
                    children_min_quanta.into_iter().collect();
                let max_min_quanta = children_min_quanta_ok?.into_iter().max().unwrap();
                Ok(max_min_quanta * weight_sum)
            }
        }
    }

    fn weight(&self) -> usize {
        match self {
            WeightTree::NonLeaf { weight, .. } | WeightTree::Leaf { weight } => *weight,
        }
    }

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

                let child = |ch: Option<Box<WeightTree>>| {
                    if let Some(c) = ch {
                        let wt = c.weight();
                        Ok::<_, Report>(Box::new(
                            c.into_flow_tree_with_quantum((wt * quantum) / sum_weights)?,
                        ))
                    } else {
                        Ok(Box::new(FlowTree::Leaf {
                            quanta: 0,
                            deficit: 0,
                            curr_qlen: 0,
                            queue: Default::default(),
                        }))
                    }
                };

                let children = [
                    child(children[0].take())?,
                    child(children[1].take())?,
                    child(children[2].take())?,
                    child(children[3].take())?,
                ];

                let sum_child_quanta: usize = children.iter().map(|c| c.quanta()).sum();
                assert_eq!(
                    sum_child_quanta, quantum,
                    "quantum did not divide evenly among children"
                );
                FlowTree::NonLeaf {
                    quanta: quantum,
                    classify: ips,
                    deficit: 0,
                    curr_qlen: 0,
                    curr_child: 0,
                    children,
                    children_remaining_quanta: [0usize; 4],
                }
            }
        })
    }
}

#[cfg(test)]
mod t {
    use super::{Scheduler, WeightTree};
    use crate::Pkt;

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
    fn parse_ip() {
        init();

        let p = "42.1.2.15";
        let m = super::parse_ip(&p).unwrap();
        assert_eq!(m, u32::from_be_bytes([42, 1, 2, 15]));

        let p = "1.1.1.1";
        let m = super::parse_ip(&p).unwrap();
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

        let wt = WeightTree::from_str(cfg_str).unwrap();
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
                    ],
                    ..
                } if matches!(&*l1, &WeightTree::Leaf { weight: 1 }) &&
                     matches!(&*l2, &WeightTree::NonLeaf {
                            weight: 2,
                            children: [
                                Some(ref l3 ),
                                Some(ref l4 ),
                                None,
                                None
                            ],
                            ..
                    } if matches!(&**l3, WeightTree::Leaf { weight: 1 }) &&
                         matches!(&**l4, WeightTree::Leaf { weight: 2 })
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
                    etherparse::IpNumber::Tcp,
                    src_ip,
                    b_ip,
                ),
                buf: vec![0u8; 100],
            })
            .unwrap();
            hwfq.enq(Pkt {
                ip_hdr: etherparse::Ipv4Header::new(
                    100,
                    64,
                    etherparse::IpNumber::Tcp,
                    src_ip,
                    d_ip,
                ),
                buf: vec![0u8; 100],
            })
            .unwrap();
            hwfq.enq(Pkt {
                ip_hdr: etherparse::Ipv4Header::new(
                    100,
                    64,
                    etherparse::IpNumber::Tcp,
                    src_ip,
                    e_ip,
                ),
                buf: vec![0u8; 100],
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
