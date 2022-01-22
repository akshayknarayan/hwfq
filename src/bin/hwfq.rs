use color_eyre::{
    eyre::{eyre, Report},
    Help,
};
use hwfq::scheduler::{Drr, Fifo};
use hwfq::Datapath;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "hwfq")]
struct Opt {
    #[structopt(short, long)]
    interface_name: String,

    #[structopt(short, long)]
    rate_bytes_per_sec: Option<usize>,

    #[structopt(short, long)]
    queue_size_bytes: usize,

    #[structopt(short, long)]
    scheduler: String,
}

pub fn main() -> Result<(), Report> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let opt = Opt::from_args();

    match opt.scheduler.as_str() {
        "none" => {
            let s = Datapath::new(opt.interface_name, None, Fifo::new(0)).unwrap();
            s.run().unwrap();
        }
        "fifo" => {
            let s = Datapath::new(
                opt.interface_name,
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
                opt.interface_name,
                Some(
                    opt.rate_bytes_per_sec
                        .ok_or(eyre!("Pacing rate is required to use scheduler"))?,
                ),
                Drr::new(opt.queue_size_bytes),
            )
            .unwrap();
            s.run().unwrap();
        }
        s => {
            return Err(eyre!("unknown scheduler {:?}", s))
                .note("supported schedulers are [none, fifo]")
        }
    }
    unreachable!()
}
