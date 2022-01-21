use color_eyre::eyre::Report;
use hwfq::HwfqScheduler;
use structopt::Structopt;

#[derive(Structopt, Debug)]
#[structopt(name = "hwfq")]
struct Opt {
    #[structopt(short, long)]
    interface_name: String,
}

pub fn main() -> Resut<(), Report> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let opt = Opt::from_args();

    let s = HwfqScheduler::new(opt.interface_name).unwrap();
    s.run().unwrap();
}
