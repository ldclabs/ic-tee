use rand::thread_rng;
use rand::RngCore;

pub mod agent;
pub mod http;
pub mod identity;
pub mod setting;

pub use identity::*;

pub fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut rng = thread_rng();
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}
