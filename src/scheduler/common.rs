use color_eyre::eyre::{bail, ensure, eyre, Report, WrapErr};

pub const MAX_NUM_CHILDREN: usize = 8;
/// A tree of weights and IP addresses to match them against.
///
/// This type is a *specification* of a weight tree. At runtime,
/// `HierarchicalDeficitWeightedRoundRobin` will convert it to a tree of queues, which it uses to
/// actually store packets.
///
/// See [`WeightTree::leaf`], [`WeightTree::parent`], [`WeightTree::add_child`], and
/// [`WeightTree::from_str`]/[`WeightTree::from_file`] for how to construct one.
///
/// We enumerate all IP addresses to match rather than using prefixes, so that we can run
/// experiments with randomly assigned IPs.
///
/// # Example
// / ```rust
// / let all_ips = [
// /     u32::from_be_bytes([10, 0, 0, 0]),
// /     u32::from_be_bytes([10, 1, 1, 1]),
// /     u32::from_be_bytes([10, 1, 2, 1]),
// / ];
// / WeightTree::parent(1)
// /     .add_child(vec![all_ips[0]], WeightTree::leaf(1))
// /     .expect("This call cannot fail, since the sub-tree is depth 1")
// /     .add_child(
// /         all_ips[1..].to_vec(),
// /         WeightTree::parent(2)
// /             .add_child(vec![all_ips[1]], WeightTree::leaf(1))
// /             .unwrap() // sub-tree of depth 1
// /             .add_child(vec![all_ips[2]], WeightTree::leaf(2))
// /             .unwrap(), // sub-tree of depth 1
// /     )
// /     .expect("We check here that the IP addresses passed to add_child match the full set in the
// /     sub-tree.");
// / ```
#[derive(Clone, Debug)]
pub enum WeightTree {
    Leaf {
        weight: usize,
        ips: Vec<u32>,
    },
    NonLeaf {
        weight: usize,
        ips: [Vec<u32>; MAX_NUM_CHILDREN],
        children: [Option<Box<WeightTree>>; MAX_NUM_CHILDREN],
    },
}

pub fn parse_ip(ip: &str) -> Result<u32, Report> {
    let ip: Vec<_> = ip.split('.').collect();
    ensure!(ip.len() == 4, "ip must be a.b.c.d");
    let (a, b, c, d) = match &ip[..] {
        &[a, b, c, d] => (a.parse()?, b.parse()?, c.parse()?, d.parse()?),
        _ => unreachable!(),
    };
    // debug!("Parsed IP: {}.{}.{}.{}", a, b, c, d);
    let ip = u32::from_be_bytes([a, b, c, d]);
    // debug!("Parsed IP: {:x}", ip);
    Ok(ip)
}

use yaml_rust::Yaml;
pub fn from_yaml(yaml: Yaml) -> Result<(Vec<u32>, WeightTree), Report> {
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
        const INIT_VEC: Vec<u32> = Vec::new();
        WeightTree::Leaf {
            weight: weight,
            ips: INIT_VEC,
        }
    }

    pub fn parent(weight: usize) -> Self {
        const INIT_VEC: Vec<u32> = Vec::new();
        const INIT_CHILD: Option<Box<WeightTree>> = None;
        WeightTree::NonLeaf {
            weight,
            ips: [INIT_VEC; MAX_NUM_CHILDREN],
            children: [INIT_CHILD; MAX_NUM_CHILDREN],
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

    /// Add a child to the weight tree which matches the IP addresses `child_ips`.
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
                let mut found = false;
                for c in 0..MAX_NUM_CHILDREN {
                    if ips[c].is_empty() {
                        ips[c] = child_ips;
                        children[c] = Some(Box::new(child));
                        found = true;
                        break;
                    }
                }

                ensure!(found, "Too many children for non-leaf node.");
                Ok(self)
            }
        }
    }

    pub fn get_min_quantum(&self) -> Result<usize, Report> {
        Ok(500)
    }

    pub fn weight(&self) -> usize {
        match self {
            WeightTree::NonLeaf { weight, .. } | WeightTree::Leaf { weight, .. } => *weight,
        }
    }
}

#[cfg(test)]
pub(crate) mod t {
    pub(crate) fn init() {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            tracing_subscriber::fmt::init();
            color_eyre::install().unwrap();
        })
    }

    #[test]
    fn parse_ip() {
        init();

        let p = "42.1.2.15";
        let m = super::parse_ip(p).unwrap();
        assert_eq!(m, u32::from_be_bytes([42, 1, 2, 15]));

        let p = "1.1.1.1";
        let m = super::parse_ip(p).unwrap();
        assert_eq!(m, u32::from_be_bytes([1, 1, 1, 1]));
    }
}
