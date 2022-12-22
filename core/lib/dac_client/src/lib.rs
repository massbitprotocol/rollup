mod celestia;
mod dac_client;
mod redis_client;
mod test;
mod utils;

use lazy_static::lazy_static;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::string::ToString;

pub use dac_client::DACClient;
lazy_static! {
    pub static ref MASSBIT_ROLLUP: String = String::from("MassbitRollup");
    pub static ref REDIS_CONN_URL: String = String::from("redis://127.0.0.1:6379");
}
pub fn create_namespace() -> String {
    let mut s = DefaultHasher::new();
    MASSBIT_ROLLUP.hash(&mut s);
    format!("{:x}", s.finish())
}

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}
