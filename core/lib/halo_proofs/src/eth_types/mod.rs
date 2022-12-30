//! Ethereum and Evm types used to deserialize responses from web3 / geth.

#![cfg_attr(docsrs, feature(doc_cfg))]
// Temporary until we have more of the crate implemented.
#![allow(dead_code)]
// We want to have UPPERCASE idents sometimes.
#![allow(non_snake_case)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
//#![deny(unsafe_code)] Allowed now until we find a
// better way to handle downcasting from Operation into it's variants.
#![allow(clippy::upper_case_acronyms)] // Too pedantic

#[macro_use]
pub mod macros;
#[macro_use]
pub mod error;
pub use error::Error;
use ethers_core::types;
pub use ethers_core::types::{
    transaction::{eip2930::AccessList, response::Transaction},
    Address, Block, Bytes, Signature, H160, H256, H64, U256, U64,
};
use halo2_proofs::{
    arithmetic::{Field as Halo2Field, FieldExt},
    halo2curves::{
        bn256::{Fq, Fr},
        group::ff::PrimeField,
    },
};
use serde::{de, Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// Trait used to reduce verbosity with the declaration of the [`FieldExt`]
/// trait and its repr.
pub trait Field: FieldExt + Halo2Field + PrimeField<Repr = [u8; 32]> {}

// Impl custom `Field` trait for BN256 Fr to be used and consistent with the
// rest of the workspace.
impl Field for Fr {}

// Impl custom `Field` trait for BN256 Frq to be used and consistent with the
// rest of the workspace.
impl Field for Fq {}

/// Trait used to define types that can be converted to a 256 bit scalar value.
pub trait ToScalar<F> {
    /// Convert the type to a scalar value.
    fn to_scalar(&self) -> Option<F>;
}

/// Trait used to convert a type to a [`Word`].
pub trait ToWord {
    /// Convert the type to a [`Word`].
    fn to_word(&self) -> Word;
}

/// Trait used to convert a type to a [`Address`].
pub trait ToAddress {
    /// Convert the type to a [`Address`].
    fn to_address(&self) -> Address;
}

/// Trait uset do convert a scalar value to a 32 byte array in big endian.
pub trait ToBigEndian {
    /// Convert the value to a 32 byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32];
}

/// Trait used to convert a scalar value to a 32 byte array in little endian.
pub trait ToLittleEndian {
    /// Convert the value to a 32 byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32];
}

// We use our own declaration of another U256 in order to implement a custom
// deserializer that can parse U256 when returned by structLogs fields in geth
// debug_trace* methods, which don't contain the `0x` prefix.
#[allow(clippy::all)]
mod uint_types {
    uint::construct_uint! {
        /// 256-bit unsigned integer.
        pub struct DebugU256(4);
    }
}
pub use uint_types::DebugU256;

impl<'de> Deserialize<'de> for DebugU256 {
    fn deserialize<D>(deserializer: D) -> Result<DebugU256, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        DebugU256::from_str(&s).map_err(de::Error::custom)
    }
}

impl<F: Field> ToScalar<F> for DebugU256 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        F::from_repr(bytes).into()
    }
}

impl ToBigEndian for DebugU256 {
    /// Encode the value as byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes
    }
}

impl ToWord for DebugU256 {
    fn to_word(&self) -> Word {
        U256(self.0)
    }
}

/// Ethereum Word (256 bits).
pub type Word = U256;

impl ToBigEndian for U256 {
    /// Encode the value as byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes
    }
}

impl ToLittleEndian for U256 {
    /// Encode the value as byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        bytes
    }
}

impl<F: Field> ToScalar<F> for U256 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        F::from_repr(bytes).into()
    }
}

impl ToAddress for U256 {
    fn to_address(&self) -> Address {
        Address::from_slice(&self.to_be_bytes()[12..])
    }
}

/// Ethereum Hash (256 bits).
pub type Hash = types::H256;

impl ToWord for Hash {
    fn to_word(&self) -> Word {
        Word::from(self.as_bytes())
    }
}

impl ToWord for Address {
    fn to_word(&self) -> Word {
        let mut bytes = [0u8; 32];
        bytes[32 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        Word::from(bytes)
    }
}

impl ToWord for bool {
    fn to_word(&self) -> Word {
        if *self {
            Word::one()
        } else {
            Word::zero()
        }
    }
}

impl ToWord for u64 {
    fn to_word(&self) -> Word {
        Word::from(*self)
    }
}

impl ToWord for usize {
    fn to_word(&self) -> Word {
        u64::try_from(*self)
            .expect("usize bigger than u64")
            .to_word()
    }
}

impl<F: Field> ToScalar<F> for Address {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        bytes[32 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        bytes.reverse();
        F::from_repr(bytes).into()
    }
}

impl<F: Field> ToScalar<F> for bool {
    fn to_scalar(&self) -> Option<F> {
        self.to_word().to_scalar()
    }
}

impl<F: Field> ToScalar<F> for u64 {
    fn to_scalar(&self) -> Option<F> {
        Some(F::from(*self))
    }
}

impl<F: Field> ToScalar<F> for usize {
    fn to_scalar(&self) -> Option<F> {
        u64::try_from(*self).ok().map(F::from)
    }
}

/// Struct used to define the storage proof
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
pub struct StorageProof {
    /// Storage key
    pub key: U256,
    /// Storage Value
    pub value: U256,
    /// Storage proof: rlp-encoded trie nodes from root to value.
    pub proof: Vec<Bytes>,
}

/// Struct used to define the result of `eth_getProof` call
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EIP1186ProofResponse {
    /// Account address
    pub address: Address,
    /// The balance of the account
    pub balance: U256,
    /// The hash of the code of the account
    pub code_hash: H256,
    /// The nonce of the account
    pub nonce: U256,
    /// SHA3 of the StorageRoot
    pub storage_hash: H256,
    /// Array of rlp-serialized MerkleTree-Nodes
    pub account_proof: Vec<Bytes>,
    /// Array of storage-entries as requested
    pub storage_proof: Vec<StorageProof>,
}

// Wrapper over u8 that provides formats the byte in hex for [`fmt::Debug`].
pub(crate) struct DebugByte(pub(crate) u8);

impl fmt::Debug for DebugByte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{:02x}", self.0))
    }
}

// Wrapper over Word reference that provides formats the word in hex for
// [`fmt::Debug`].
pub(crate) struct DebugWord<'a>(pub(crate) &'a Word);

impl<'a> fmt::Debug for DebugWord<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("0x{:x}", self.0))
    }
}

#[macro_export]
/// Create an [`Address`] from a hex string.  Panics on invalid input.
macro_rules! address {
    ($addr_hex:expr) => {{
        use std::str::FromStr;
        $crate::eth_types::Address::from_str(&$addr_hex).expect("invalid hex Address")
    }};
}

#[macro_export]
/// Create a [`Word`] from a hex string.  Panics on invalid input.
macro_rules! word {
    ($word_hex:expr) => {
        $crate::eth_types::Word::from_str_radix(&$word_hex, 16).expect("invalid hex Word")
    };
}

#[macro_export]
/// Create a [`Word`] to [`Word`] HashMap from pairs of hex strings.  Panics on
/// invalid input.
macro_rules! word_map {
    () => {
        std::collections::HashMap::new()
    };
    ($($key_hex:expr => $value_hex:expr),*) => {
        {
            std::collections::HashMap::from_iter([(
                    $(word!($key_hex), word!($value_hex)),*
            )])
        }
    }
}
