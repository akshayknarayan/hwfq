use color_eyre::{eyre::eyre, Report};
use hwfq::scheduler::HierarchicalDeficitWeightedRoundRobin;
use hwfq::scheduler::common::WeightTree;

fn main() -> Result<(), Report> {
    let mut args = std::env::args();
    let file_name = args
        .nth(1)
        .ok_or_else(|| eyre!("need config file as argument"))?;

    dbg!(&file_name);

    let wt = WeightTree::from_file(file_name)?;
    dbg!(&wt);

    let hwfq = HierarchicalDeficitWeightedRoundRobin::new(0, true, wt)?;
    dbg!(&hwfq);

    Ok(())
}
