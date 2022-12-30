use std::str::FromStr;

//use halo2_proofs::arithmetic::FieldExt;
use zksync_crypto::circuit::account::CircuitAccount;
use zksync_crypto::circuit::account::CircuitAccountTree;
use zksync_types::Account;
use zksync_types::AccountId;
use zksync_types::AccountMap;
use zksync_types::Address;

use crate::state::RollupState;

use super::account::WitnessTestAccount;
pub const FEE_ACCOUNT_ID: AccountId = AccountId(0);
pub const BLOCK_TIMESTAMP: u64 = 0x12345678u64;

/// Helper structure to generate `ZkSyncState` and `CircuitAccountTree`.
#[derive(Debug)]
pub struct RollupStateGenerator;

impl RollupStateGenerator {
    fn create_state(accounts: AccountMap) -> (RollupState, CircuitAccountTree) {
        let plasma_state = RollupState::from_acc_map(accounts);

        let mut circuit_account_tree =
            CircuitAccountTree::new(zksync_crypto::params::account_tree_depth());
        for (id, account) in plasma_state.get_accounts() {
            circuit_account_tree.insert(id, CircuitAccount::from(account))
        }

        (plasma_state, circuit_account_tree)
    }

    pub fn generate(accounts: &[WitnessTestAccount]) -> (RollupState, CircuitAccountTree) {
        let accounts: Vec<_> = accounts
            .iter()
            .map(|acc| (acc.id, acc.account.clone()))
            .collect();

        let accounts = if accounts.iter().any(|(id, _)| *id == FEE_ACCOUNT_ID) {
            println!(
                "Note: AccountId {} is an existing fee account",
                *FEE_ACCOUNT_ID
            );
            accounts.into_iter().collect()
        } else {
            std::iter::once((
                FEE_ACCOUNT_ID,
                Account::default_with_address(
                    &Address::from_str("feeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap(),
                ),
            ))
            .chain(accounts)
            .collect()
        };

        Self::create_state(accounts)
    }
}
