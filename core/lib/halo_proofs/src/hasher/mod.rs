pub mod keccak256;
use halo2_proofs::halo2curves::pairing::Engine;
//pub mod rescue_hasher;
//pub use rescue_hasher::RescueHasher;
//pub mod simple_hasher;
//pub use simple_hasher::SimpleHasher;
pub trait RescueEngine: Engine {
    type Fr: ff::PrimeField + ff::Field;
}
