use color_eyre::eyre::Report;
use hwfq::Datapath;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "hwfq")]
struct Opt {
    #[structopt(short, long)]
    interface_name: String,

    #[structopt(short, long)]
    rate_bytes_per_sec: usize,

    #[structopt(short, long)]
    queue_size_bytes: usize,
}

pub fn main() -> Result<(), Report> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let opt = Opt::from_args();

    let s = Datapath::new(
        opt.interface_name,
        opt.rate_bytes_per_sec,
        opt.queue_size_bytes,
    )
    .unwrap();
    s.run().unwrap();
    unreachable!()
}
