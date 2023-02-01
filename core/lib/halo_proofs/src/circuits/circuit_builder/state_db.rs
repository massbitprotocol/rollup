//! Implementation of an in-memory key-value database to represent the
//! Ethereum State Trie.

use eth_types::{Address, Hash, ToLittleEndian, Word, H256, U256};
use ethers_core::utils::keccak256;
use lazy_static::lazy_static;
use std::collections::{HashMap, HashSet};
use zksync_crypto::params;
use zksync_crypto::primitives::{GetBits, GetBitsFixed};
//use zksync_types::Account;
use ethers_signers::{LocalWallet, Signer};
use mock::MOCK_CHAIN_ID;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zksync_types::Nonce;
use zksync_types::SparseMerkleTree;
use zksync_types::TokenId;
use zksync_utils::BigUintSerdeWrapper;
lazy_static! {
    static ref ACCOUNT_ZERO: Account = Account::zero();
    static ref VALUE_ZERO: Word = Word::zero();
    static ref CODE_HASH_ZERO: Hash = H256(keccak256(&[]));
}
pub use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
pub type KeccakHasher = crate::hasher::keccak256::Keccak256Hasher;
pub type AccountTree = SparseMerkleTree<Account, Fr, KeccakHasher>;
/// Memory storage for contract code by code hash.
#[derive(Debug, Clone)]
pub struct CodeDB(pub HashMap<Hash, Vec<u8>>);

impl Default for CodeDB {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeDB {
    /// Create a new empty Self.
    pub fn new() -> Self {
        Self(HashMap::new())
    }
    /// Insert code indexed by code hash, and return the code hash.
    pub fn insert(&mut self, code: Vec<u8>) -> Hash {
        let hash = H256(keccak256(&code));
        self.0.insert(hash, code);
        hash
    }
}

/// Account of the Ethereum State Trie, which contains an in-memory key-value
/// database that represents the Account Storage Trie.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Account {
    pub address: Address,
    /// Balance
    pub balance: Word,
    pub balances: HashMap<TokenId, BigUintSerdeWrapper>,
    /// Current nonce of the account. All the transactions require nonce field to be set in
    /// order to not allow double spend, and the nonce must increment by one after each operation.
    /// Nonce
    pub nonce: Word,
    /// Storage key-value map
    pub storage: HashMap<Word, Word>,
    /// Code hash
    pub code_hash: Hash,
}
// impl GetBits for Word {
//     fn get_bits_le(&self) -> Vec<bool> {
//         let mut acc = Vec::new();
//         let mut i = *self + 1;
//         for _ in 0..16 {
//             acc.push(i & 1 == 1);
//             i >>= 1;
//         }
//         acc
//     }
// }
impl Account {
    /// Return an empty account, with all values set at zero.
    pub fn zero() -> Self {
        Self {
            nonce: Word::zero(),
            balance: Word::zero(),
            storage: HashMap::new(),
            code_hash: *CODE_HASH_ZERO,
            address: Address::zero(),
            balances: HashMap::new(),
        }
    }

    /// Return if account is empty or not.
    pub fn is_empty(&self) -> bool {
        self.nonce.is_zero()
            && self.balance.is_zero()
            && self.storage.is_empty()
            && self.code_hash.eq(&CODE_HASH_ZERO)
    }
}
impl Account {
    pub fn from_address(address: Address) -> Self {
        Self {
            nonce: Word::zero(),
            balance: Word::zero(),
            storage: HashMap::new(),
            code_hash: *CODE_HASH_ZERO,
            address,
            balances: HashMap::new(),
        }
    }
}
impl GetBits for Account {
    fn get_bits_le(&self) -> Vec<bool> {
        // debug_assert_eq!(
        //     params::FR_BIT_WIDTH,
        //     E::Fr::NUM_BITS as usize,
        //     "FR bit width is not equal to field bit width"
        // );
        let mut leaf_content = Vec::new();

        leaf_content.extend(get_bits_le(&self.nonce)); //32
        leaf_content.extend(get_bits_le(&self.balance));

        // // calculate hash of the subroot using algebraic hash
        // let state_root = self.get_state_root();

        // let mut state_tree_hash_bits = state_root.get_bits_le_fixed(params::FR_BIT_WIDTH);
        // state_tree_hash_bits.resize(params::FR_BIT_WIDTH_PADDED, false);

        // leaf_content.extend(state_tree_hash_bits.into_iter());

        // assert_eq!(
        //     leaf_content.len(),
        //     params::LEAF_DATA_BIT_WIDTH,
        //     "Account bit width mismatch"
        // );

        leaf_content
    }
}
fn get_bits_le(value: &Word) -> Vec<bool> {
    let mut acc = Vec::new();
    let mut i = *value + 1;
    let bytes = value.to_le_bytes();
    for b in bytes.into_iter() {
        let mut i = b;
        for _ in 0..8 {
            acc.push(i & 1 == 1);
            i >>= 1;
        }
    }
    acc
}
///Generate account_tree
pub fn generate_account_tree(tree_depth: usize) -> AccountTree {
    let mut account_tree = AccountTree::new(tree_depth);
    let size = 1 << tree_depth;
    let chain_id = (*MOCK_CHAIN_ID).as_u64();
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    for i in 1..size {
        let wallet = LocalWallet::new(&mut rng).with_chain_id(chain_id);
        let account = Account::from_address(wallet.address().clone());
        account_tree.insert(i, account);
    }

    account_tree
}

/// In-memory key-value database that represents the Ethereum State Trie.
#[derive(Debug, Clone)]
pub struct StateDB {
    state: HashMap<Address, Account>,
    account_tree: AccountTree,
    // Fields with transaction lifespan, will be clear in `clear_access_list_and_refund`.
    access_list_account: HashSet<Address>,
    access_list_account_storage: HashSet<(Address, U256)>,
    // `dirty_storage` contains writes during current transaction.
    // When current transaction finishes, `dirty_storage` will be committed into `state`.
    // The reason why we need this is that EVM needs committed state, namely
    // state before current transaction, to calculate gas cost for some opcodes like sstore.
    // So both dirty storage and committed storage are needed.
    dirty_storage: HashMap<(Address, Word), Word>,
    // Accounts that have been through `SELFDESTRUCT` under the situation that `is_persistent` is
    // `true`. These accounts will be reset once `commit_tx` is called.
    destructed_account: HashSet<Address>,
    refund: u64,
}
impl Default for StateDB {
    fn default() -> Self {
        Self {
            state: HashMap::new(),
            account_tree: AccountTree::new(params::ACCOUNT_TREE_DEPTH),
            access_list_account: HashSet::new(),
            access_list_account_storage: HashSet::new(),
            dirty_storage: HashMap::new(),
            destructed_account: HashSet::new(),
            refund: 0,
        }
    }
}
impl StateDB {
    /// Create an empty Self
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
            account_tree: AccountTree::new(params::ACCOUNT_TREE_DEPTH),
            access_list_account: HashSet::new(),
            access_list_account_storage: HashSet::new(),
            dirty_storage: HashMap::new(),
            destructed_account: HashSet::new(),
            refund: 0,
        }
    }
    pub fn set_account_tree(&mut self, account_tree: AccountTree) {
        self.account_tree = account_tree;
    }
    pub fn get_account_tree(&self) -> AccountTree {
        self.account_tree.clone()
    }
    /// Set an [`Account`] at `addr` in the StateDB.
    pub fn set_account(&mut self, addr: &Address, acc: Account) {
        self.state.insert(*addr, acc);
    }

    /// Get a reference to the [`Account`] at `addr`.  Returns false and a zero
    /// [`Account`] when the [`Account`] wasn't found in the state.
    pub fn get_account(&self, addr: &Address) -> (bool, &Account) {
        match self.state.get(addr) {
            Some(acc) => (true, acc),
            None => (false, &(*ACCOUNT_ZERO)),
        }
    }

    /// Get a mutable reference to the [`Account`] at `addr`.  If the
    /// [`Account`] is not found in the state, a zero one will be inserted
    /// and returned along with false.
    pub fn get_account_mut(&mut self, addr: &Address) -> (bool, &mut Account) {
        let found = if self.state.contains_key(addr) {
            true
        } else {
            self.state.insert(*addr, Account::zero());
            false
        };
        (found, self.state.get_mut(addr).expect("addr not inserted"))
    }

    /// Get a reference to the storage value from [`Account`] at `addr`, at
    /// `key`.  Returns false and a zero [`Word`] when the [`Account`] or `key`
    /// wasn't found in the state.
    /// Returns dirty storage state, which includes writes in current tx
    pub fn get_storage(&self, addr: &Address, key: &Word) -> (bool, &Word) {
        match self.dirty_storage.get(&(*addr, *key)) {
            Some(v) => (true, v),
            None => self.get_committed_storage(addr, key),
        }
    }

    /// Get a reference to the storage value from [`Account`] at `addr`, at
    /// `key`.  Returns false and a zero [`Word`] when the [`Account`] or `key`
    /// wasn't found in the state.
    /// Returns committed storage, which is storage state before current tx
    pub fn get_committed_storage(&self, addr: &Address, key: &Word) -> (bool, &Word) {
        let (_, acc) = self.get_account(addr);
        match acc.storage.get(key) {
            Some(value) => (true, value),
            None => (false, &(*VALUE_ZERO)),
        }
    }

    /// Get a mutable reference to the storage value from [`Account`] at `addr`,
    /// at `key`.  Returns false when the [`Account`] or `key` wasn't found in
    /// the state and it is created.  If the [`Account`] or `key` is not found
    /// in the state, a zero [`Account`] will be inserted, a zero value will
    /// be inserted at `key` in its storage, and the value will be returned
    /// along with false.
    pub fn get_storage_mut(&mut self, addr: &Address, key: &Word) -> (bool, &mut Word) {
        let (_, acc) = self.get_account_mut(addr);
        let found = if acc.storage.contains_key(key) {
            true
        } else {
            acc.storage.insert(*key, Word::zero());
            false
        };
        (found, acc.storage.get_mut(key).expect("key not inserted"))
    }

    /// Set storage value at `addr` and `key`.
    /// Writes into dirty_storage during transaction execution.
    /// After transaction execution, `dirty_storage` is committed into `storage`
    /// in `commit_tx` method.
    pub fn set_storage(&mut self, addr: &Address, key: &Word, value: &Word) {
        self.dirty_storage.insert((*addr, *key), *value);
    }

    /// Get nonce of account with `addr`.
    pub fn get_nonce(&mut self, addr: &Address) -> u64 {
        let (_, account) = self.get_account(addr);
        account.nonce.as_u64()
    }

    /// Increase nonce of account with `addr` and return the previous value.
    pub fn increase_nonce(&mut self, addr: &Address) -> u64 {
        let (_, account) = self.get_account_mut(addr);
        let nonce = account.nonce.as_u64();
        account.nonce = account.nonce + 1;
        nonce
    }

    /// Check whether `addr` exists in account access list.
    pub fn check_account_in_access_list(&self, addr: &Address) -> bool {
        self.access_list_account.contains(addr)
    }

    /// Add `addr` into account access list. Returns `true` if it's not in the
    /// access list before.
    pub fn add_account_to_access_list(&mut self, addr: Address) -> bool {
        self.access_list_account.insert(addr)
    }

    /// Remove `addr` from account access list.
    pub fn remove_account_from_access_list(&mut self, addr: &Address) {
        let exist = self.access_list_account.remove(addr);
        debug_assert!(exist);
    }

    /// Check whether `(addr, key)` exists in account storage access list.
    pub fn check_account_storage_in_access_list(&self, pair: &(Address, Word)) -> bool {
        self.access_list_account_storage.contains(pair)
    }

    /// Add `(addr, key)` into account storage access list. Returns `true` if
    /// it's not in the access list before.
    pub fn add_account_storage_to_access_list(&mut self, (addr, key): (Address, Word)) -> bool {
        self.access_list_account_storage.insert((addr, key))
    }

    /// Remove `(addr, key)` from account storage access list.
    pub fn remove_account_storage_from_access_list(&mut self, pair: &(Address, Word)) {
        let exist = self.access_list_account_storage.remove(pair);
        debug_assert!(exist);
    }

    /// Set account as self destructed.
    pub fn destruct_account(&mut self, addr: Address) {
        self.destructed_account.insert(addr);
    }

    /// Retrieve refund.
    pub fn refund(&self) -> u64 {
        self.refund
    }

    /// Set refund
    pub fn set_refund(&mut self, value: u64) {
        self.refund = value;
    }

    /// Clear access list and refund, and commit dirty storage.
    /// It should be invoked before processing
    /// with new transaction with the same [`StateDB`].
    pub fn commit_tx(&mut self) {
        self.access_list_account = HashSet::new();
        self.access_list_account_storage = HashSet::new();
        for ((addr, key), value) in self.dirty_storage.clone() {
            let (_, ptr) = self.get_storage_mut(&addr, &key);
            *ptr = value;
        }
        self.dirty_storage = HashMap::new();
        for addr in self.destructed_account.clone() {
            let (_, account) = self.get_account_mut(&addr);
            *account = ACCOUNT_ZERO.clone();
        }
        self.refund = 0;
    }
}

#[cfg(test)]
mod statedb_tests {
    use super::*;
    use eth_types::address;

    #[test]
    fn statedb() {
        let addr_a = address!("0x0000000000000000000000000000000000000001");
        let addr_b = address!("0x0000000000000000000000000000000000000002");
        let mut statedb = StateDB::new();

        // Get non-existing account
        let (found, acc) = statedb.get_account(&addr_a);
        assert!(!found);
        assert_eq!(acc, &Account::zero());

        // Get non-existing storage key for non-existing account
        let (found, value) = statedb.get_storage(&addr_a, &Word::from(2));
        assert!(!found);
        assert_eq!(value, &Word::zero());

        // Get mut non-existing account and set nonce
        let (found, acc) = statedb.get_account_mut(&addr_a);
        assert!(!found);
        assert_eq!(acc, &Account::zero());
        acc.nonce = Word::from(100);

        // Get existing account and check nonce
        let (found, acc) = statedb.get_account(&addr_a);
        assert!(found);
        assert_eq!(acc.nonce, Word::from(100));

        // Get non-existing storage key for existing account and set value
        let (found, value) = statedb.get_storage_mut(&addr_a, &Word::from(2));
        assert!(!found);
        assert_eq!(value, &Word::zero());
        *value = Word::from(101);

        // Get existing storage key and check value
        let (found, value) = statedb.get_storage(&addr_a, &Word::from(2));
        assert!(found);
        assert_eq!(value, &Word::from(101));

        // Get non-existing storage key for non-existing account and set value
        let (found, value) = statedb.get_storage_mut(&addr_b, &Word::from(3));
        assert!(!found);
        assert_eq!(value, &Word::zero());
        *value = Word::from(102);

        // Get existing account and check nonce
        let (found, acc) = statedb.get_account(&addr_b);
        assert!(found);
        assert_eq!(acc.nonce, Word::zero());

        // Get existing storage key and check value
        let (found, value) = statedb.get_storage(&addr_b, &Word::from(3));
        assert!(found);
        assert_eq!(value, &Word::from(102));
    }
}
