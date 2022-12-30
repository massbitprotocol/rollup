use std::collections::HashMap;

use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::Error;
use zksync_basic_types::{AccountId, Address, TokenId};
use zksync_crypto::{
    merkle_tree::TreeMemoryUsage,
    params::{self, NFT_STORAGE_ACCOUNT_ID},
};
use zksync_state::state::BalanceUpdate;
use zksync_types::{Account, AccountMap, AccountUpdate, NFT};

use crate::{AccountTree, Fr};

/*
 * Load current state into circuit
 */
pub trait State<F: FieldExt> {
    fn load_state(&self, layouter: impl Layouter<F>) -> Result<(), Error>;
}
#[derive(Debug, Clone)]
pub struct RollupState {
    /// Accounts stored in a sparse Merkle tree
    balance_tree: AccountTree,

    account_id_by_address: HashMap<Address, AccountId>,

    pub nfts: HashMap<TokenId, NFT>,

    next_free_id: AccountId,
}
impl Default for RollupState {
    fn default() -> Self {
        RollupState {
            balance_tree: AccountTree::new(1),
            account_id_by_address: Default::default(),
            nfts: Default::default(),
            next_free_id: Default::default(),
        }
    }
}
impl RollupState {
    pub fn empty() -> Self {
        let tree_depth = params::account_tree_depth();
        let balance_tree = AccountTree::new(tree_depth);
        Self {
            balance_tree,
            account_id_by_address: HashMap::new(),
            next_free_id: AccountId(0),
            nfts: HashMap::new(),
        }
    }

    pub fn from_acc_map(accounts: AccountMap) -> Self {
        let mut empty = Self::empty();

        let mut next_free_id = 0;
        for account in &accounts {
            if account.0 != &NFT_STORAGE_ACCOUNT_ID {
                next_free_id = std::cmp::max(next_free_id, **account.0 + 1);
            }
        }
        empty.next_free_id = AccountId(next_free_id as u32);

        for (id, account) in accounts {
            empty.insert_account(id, account);
        }
        empty
    }

    pub fn new(
        balance_tree: AccountTree,
        account_id_by_address: HashMap<Address, AccountId>,
        nfts: HashMap<TokenId, NFT>,
    ) -> Self {
        let mut next_free_id = 0;
        for index in balance_tree.items.keys() {
            if *index != NFT_STORAGE_ACCOUNT_ID.0 as u64 {
                next_free_id = std::cmp::max(next_free_id, *index + 1);
            }
        }

        Self {
            balance_tree,
            account_id_by_address,
            next_free_id: AccountId(next_free_id as u32),
            nfts,
        }
    }

    pub fn tree_memory_stats(&self) -> TreeMemoryUsage {
        self.balance_tree.memory_stats()
    }

    pub fn get_accounts(&self) -> Vec<(u32, Account)> {
        self.balance_tree
            .items
            .iter()
            .filter_map(|a| {
                if a.1 == &Account::default() {
                    None
                } else {
                    Some((*a.0 as u32, a.1.clone()))
                }
            })
            .collect()
    }

    pub fn root_hash(&self) -> Fr {
        let start = std::time::Instant::now();
        let hash = self.balance_tree.root_hash();
        metrics::histogram!("root_hash", start.elapsed());
        hash
    }

    pub fn get_account(&self, account_id: AccountId) -> Option<Account> {
        let start = std::time::Instant::now();
        let account = self
            .balance_tree
            .get(*account_id)
            .filter(|acc| !acc.is_default())
            .cloned();
        metrics::histogram!("state.get_account", start.elapsed());

        account
    }

    pub fn update_account(
        &mut self,
        account_id: AccountId,
        token: TokenId,
        update: BalanceUpdate,
        nonce_update: u32,
    ) -> (AccountId, AccountUpdate) {
        let mut account = self.get_account(account_id).unwrap();
        let old_balance = account.get_balance(token);

        match update {
            BalanceUpdate::Add(amount) => account.add_balance(token, &amount),
            BalanceUpdate::Sub(amount) => account.sub_balance(token, &amount),
        }

        let new_balance = account.get_balance(token);
        let old_nonce = account.nonce;
        *account.nonce += nonce_update;
        let new_nonce = account.nonce;
        self.insert_account(account_id, account);

        (
            account_id,
            AccountUpdate::UpdateBalance {
                balance_update: (token, old_balance, new_balance),
                old_nonce,
                new_nonce,
            },
        )
    }
    #[doc(hidden)] // Public for benches.
    pub fn insert_account(&mut self, id: AccountId, account: Account) {
        // Even though account ids are expected to be sequential,
        // we have to allow gaps between them since such data
        // is already published on chain. Otherwise, restore would not
        // be possible.

        self.account_id_by_address.insert(account.address, id);
        self.balance_tree.insert(*id, account);
        if id != NFT_STORAGE_ACCOUNT_ID && id >= self.next_free_id {
            self.next_free_id = id + 1;
        }
    }

    #[allow(dead_code)]
    pub(crate) fn remove_account(&mut self, id: AccountId) {
        assert_eq!(*id, *self.next_free_id - 1);

        if let Some(account) = self.get_account(id) {
            self.account_id_by_address.remove(&account.address);
            self.balance_tree.remove(*id);
            *self.next_free_id -= 1;
        }
    }
}
impl<F: FieldExt> State<F> for RollupState {
    fn load_state(&self, layouter: impl Layouter<F>) -> Result<(), Error> {
        println!("Load RollupState state");
        Ok(())
    }
}
