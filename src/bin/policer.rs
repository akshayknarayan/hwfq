use std::str::FromStr;

use clap::Parser;
use color_eyre::eyre::{eyre, Report};
use hwfq::scheduler::htb::{Class, ClassedTokenBucket, TokenBucket};
use hwfq::Datapath;

#[derive(Clone, Copy, Debug)]
struct ClassOpt {
    dport: u16,
    rate: usize,
}

impl FromStr for ClassOpt {
    type Err = Report;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut sp = s.split('=');
        let dport = sp
            .next()
            .ok_or_else(|| eyre!("dport=rate format for class"))?
            .parse()?;
        let rate = sp
            .next()
            .ok_or_else(|| eyre!("dport=rate format for class"))?
            .parse()?;
        Ok(ClassOpt { dport, rate })
    }
}

impl From<ClassOpt> for Class {
    fn from(c: ClassOpt) -> Class {
        if c.dport == 0 {
            Class::new(None, TokenBucket::new(c.rate))
        } else {
            Class::new(Some(c.dport), TokenBucket::new(c.rate))
        }
    }
}

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
    class: Vec<ClassOpt>,

    #[arg(long)]
    default_class: Option<ClassOpt>,
}

pub fn main() -> Result<(), Report> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let opt = Opt::parse();

    let ctb = ClassedTokenBucket::new(
        opt.queue_size_bytes,
        opt.class.into_iter().map(Into::into),
        opt.default_class.map(Into::into),
    )?;
    let s = Datapath::new(
        &opt.listen_interface,
        &opt.fwd_address,
        opt.rate_bytes_per_sec,
        ctb,
    )?;
    s.run()
}
