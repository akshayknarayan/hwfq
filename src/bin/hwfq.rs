use hwfq::HwfqScheduler;

pub fn main() {
    let s = HwfqScheduler::new("ens3".to_owned()).unwrap();
    s.run().unwrap();
}
