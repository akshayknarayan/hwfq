use clap::Parser;
use color_eyre::eyre::Report;
use hwfq::scheduler::htb::{parse_args::Opt as CtbOpt, ClassedTokenBucket};
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

    #[command(flatten)]
    qargs: CtbOpt,
}

pub fn main() -> Result<(), Report> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let opt = Opt::parse();

    let ctb = ClassedTokenBucket::try_from(opt.qargs)?;
    let s = Datapath::new(
        &opt.listen_interface,
        &opt.fwd_address,
        opt.rate_bytes_per_sec,
        ctb,
    )?;
    s.run()
}
