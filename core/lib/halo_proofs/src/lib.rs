#![feature(adt_const_params)]
#![feature(iterator_try_collect)]
//pub mod bus_mapping;
pub mod chips;
pub mod circuits;
pub mod gadgets;
pub mod hasher;
pub mod instructions;
pub mod state;
pub mod tests;
pub mod transactions;
//use franklin_crypto::bellman::pairing::bn256;
pub use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
pub use zkevm_circuits::impl_expr;
//use zksync_crypto::merkle_tree::rescue_hasher;
use zksync_types::{Account, SparseMerkleTree};
//
pub type Engine = Bn256;
pub type Fp = halo2_proofs::halo2curves::pasta::pallas::Base;
//pub type RescueHasher<T> = hasher::RescueHasher<T>;
//pub type SimpleHasher = hasher::SimpleHasher;
pub type KeccakHasher = hasher::keccak256::Keccak256Hasher;
//pub type AccountTree = SparseMerkleTree<Account, Fp, RescueHasher<Engine>>;
pub type AccountTree = SparseMerkleTree<Account, Fr, KeccakHasher>;

pub mod evm_circuit {
    pub mod param {
        pub use crate::circuits::evm_circuit::param::*;
    }
    pub mod step {
        pub use crate::circuits::evm_circuit::step::*;
    }
    pub mod table {
        pub use crate::circuits::evm_circuit::table::*;
    }
    pub mod util {
        pub use crate::circuits::evm_circuit::util::*;
        pub use crate::circuits::util::Expr;
    }
    pub mod witness {
        pub use crate::circuits::witness::*;
    }
    pub use halo2_proofs::plonk::{Advice, Column, Fixed};
}
pub mod copy_circuit {
    use crate::circuits::evm_circuit::util::RandomLinearCombination;
    use bus_mapping::circuit_input_builder::NumberOrHash;
    use eth_types::Field;
    use halo2_proofs::circuit::Value;
    /// Encode the type `NumberOrHash` into a field element
    pub fn number_or_hash_to_field<F: Field>(v: &NumberOrHash, challenge: Value<F>) -> Value<F> {
        match v {
            NumberOrHash::Number(n) => Value::known(F::from(*n as u64)),
            NumberOrHash::Hash(h) => {
                // since code hash in the bytecode table is represented in
                // the little-endian form, we reverse the big-endian bytes
                // of H256.
                let le_bytes = {
                    let mut b = h.to_fixed_bytes();
                    b.reverse();
                    b
                };
                challenge.map(|challenge| {
                    RandomLinearCombination::random_linear_combine(le_bytes, challenge)
                })
            }
        }
    }
}
pub mod exp_circuit {
    /// The number of rows assigned for each step in an exponentiation trace.
    pub const OFFSET_INCREMENT: usize = 7usize;
    /// The number of rows required for the exponentiation table within the circuit
    /// for each step.
    pub const ROWS_PER_STEP: usize = 4usize;
}
pub mod keccak_circuit {
    pub use crate::circuits::keccak_circuit::*;
}
pub mod util {
    pub use crate::circuits::util::*;
}
pub mod table {
    pub use crate::circuits::table::{
        AccountFieldTag, BlockContextFieldTag, BlockTable, BytecodeFieldTag, BytecodeTable,
        CallContextFieldTag, CopyTable, ExpTable, KeccakTable, LookupTable, MptTable, ProofType,
        RwTable, RwTableTag, TxContextFieldTag, TxFieldTag, TxLogFieldTag, TxReceiptFieldTag,
        TxTable,
    };
    // pub use zkevm_circuits::table::{
    //     AccountFieldTag, BlockContextFieldTag, BlockTable, BytecodeFieldTag, BytecodeTable,
    //     CallContextFieldTag, CopyTable, ExpTable, KeccakTable, LookupTable, MptTable, ProofType,
    //     RwTable, RwTableTag, TxContextFieldTag, TxFieldTag, TxLogFieldTag, TxReceiptFieldTag,
    //     TxTable,
    // };
}
pub mod witness {
    pub use crate::circuits::witness::*;
}
