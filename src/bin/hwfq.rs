use color_eyre::{
    eyre::{eyre, Report},
    Help,
};
use hwfq::scheduler::{Drr, Fifo, HierarchicalDeficitWeightedRoundRobin, HierarchicalApproximateFairDropping, ApproximateFairDropping};
use hwfq::scheduler::common::WeightTree;
use hwfq::Datapath;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "hwfq")]
struct Opt {
    #[structopt(short, long)]
    fwd_address: String,

    #[structopt(short, long, default_value = "hwfq-%d")]
    listen_interface: String,

    #[structopt(short, long)]
    rate_bytes_per_sec: Option<usize>,

    #[structopt(short, long)]
    queue_size_bytes: usize,

    #[structopt(long)]
    receiver_weights: bool,

    #[structopt(short, long)]
    scheduler: String,

    #[structopt(short, long, required_if("scheduler", "hwfq"))]
    weights_cfg: Option<std::path::PathBuf>,

    #[structopt(long, default_value = "0.1")]
    sample_prob: f64,
}

pub fn main() -> Result<(), Report> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let opt = Opt::from_args();

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
                Drr::new(opt.queue_size_bytes),
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
            let cfg = opt.weights_cfg.unwrap();
            let afd = ApproximateFairDropping::new(
                opt.sample_prob,
            );
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
