use clap::Parser;
use color_eyre::{
    eyre::{eyre, Report},
    Help,
};
use hwfq::scheduler::weight_tree::WeightTree;
use hwfq::scheduler::{
    drr::Drr, ApproximateFairDropping, Fifo, HierarchicalApproximateFairDropping,
    HierarchicalDeficitWeightedRoundRobin,
};
use hwfq::Datapath;

#[derive(Parser, Debug)]
#[command(name = "hwfq")]
struct Opt {
    #[arg(short, long)]
    fwd_address: String,

    #[arg(short, long, default_value = "hwfq-%d")]
    listen_interface: String,

    #[arg(short, long)]
    rate_bytes_per_sec: Option<usize>,

    #[arg(short, long)]
    queue_size_bytes: usize,

    #[arg(long)]
    receiver_weights: bool,

    #[arg(short, long)]
    scheduler: String,

    #[arg(short, long, required_if_eq("scheduler", "hwfq"))]
    weights_cfg: Option<std::path::PathBuf>,

    #[arg(long, default_value = "0.1")]
    sample_prob: f64,
}

pub fn main() -> Result<(), Report> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let opt = Opt::parse();

    match opt.scheduler.as_str() {
        "none" => {
            let s =
                Datapath::new(&opt.listen_interface, &opt.fwd_address, None, Fifo::new(0)).unwrap();
            s.run().unwrap();
        }
        "fifo" => {
            let s = Datapath::new(
                &opt.listen_interface,
                &opt.fwd_address,
                Some(
                    opt.rate_bytes_per_sec
                        .ok_or(eyre!("Pacing rate is required to use scheduler"))?,
                ),
                Fifo::new(opt.queue_size_bytes),
            )
            .unwrap();
            s.run().unwrap();
        }
        "drr" => {
            let s = Datapath::new(
                &opt.listen_interface,
                &opt.fwd_address,
                Some(
                    opt.rate_bytes_per_sec
                        .ok_or(eyre!("Pacing rate is required to use scheduler"))?,
                ),
                Drr::<false, std::io::Empty>::new(opt.queue_size_bytes).unwrap(),
            )
            .unwrap();
            s.run().unwrap();
        }
        "hwfq" => {
            let cfg = opt.weights_cfg.unwrap();
            let wt = WeightTree::from_file(&cfg);
            let hwfq = HierarchicalDeficitWeightedRoundRobin::new(
                opt.queue_size_bytes,
                !opt.receiver_weights,
                wt?,
            )?;
            let s = Datapath::new(
                &opt.listen_interface,
                &opt.fwd_address,
                Some(
                    opt.rate_bytes_per_sec
                        .ok_or(eyre!("Pacing rate is required to use scheduler"))?,
                ),
                hwfq,
            )?;
            s.run().unwrap();
        }
        "afd" => {
            let afd = ApproximateFairDropping::new(opt.sample_prob);
            let s = Datapath::new(
                &opt.listen_interface,
                &opt.fwd_address,
                Some(
                    opt.rate_bytes_per_sec
                        .ok_or(eyre!("Pacing rate is required to use scheduler"))?,
                ),
                afd,
            )?;
            s.run().unwrap();
        }
        "hafd" => {
            let cfg = opt.weights_cfg.unwrap();
            let wt = WeightTree::from_file(&cfg);
            let hafd = HierarchicalApproximateFairDropping::new(
                opt.sample_prob,
                wt?,
                !opt.receiver_weights,
                Some(
                    opt.rate_bytes_per_sec
                        .ok_or(eyre!("Pacing rate is required to use scheduler"))?
                        as f64,
                ),
            );
            let s = Datapath::new(
                &opt.listen_interface,
                &opt.fwd_address,
                Some(
                    opt.rate_bytes_per_sec
                        .ok_or(eyre!("Pacing rate is required to use scheduler"))?,
                ),
                hafd,
            )?;
            s.run().unwrap();
        }
        s => {
            return Err(eyre!("unknown scheduler {:?}", s))
                .note("supported schedulers are [none, fifo]")
        }
    }
    unreachable!()
}
