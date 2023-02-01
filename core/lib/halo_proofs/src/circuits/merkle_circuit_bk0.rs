use super::circuit_builder::state_db::AccountTree;
use super::circuit_builder::StateDB;
use super::params::N_BYTES_WORD;
use crate::table::{LookupTable, MptTable, RwTable, RwTableTag};
use crate::util::{Challenges, Expr, SubCircuit, SubCircuitConfig};
use crate::witness::{self, MptUpdates, Rw, RwMap};
use crate::Fr;
//use constraint_builder::{ConstraintBuilder, MptUpdateTableQueries, Queries, RwTableQueries};
use eth_types::{Address, Field};
use gadgets::binary_number::{BinaryNumberChip, BinaryNumberConfig};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase,
        VirtualCells,
    },
    poly::Rotation,
};
use zksync_crypto::merkle_tree::hasher::Hasher;
// use lexicographic_ordering::Config as LexicographicOrderingConfig;
// use lexicographic_ordering::LimbIndex;
// use lookups::{Chip as LookupsChip, Config as LookupsConfig, Queries as LookupsQueries};
// use multiple_precision_integer::{Chip as MpiChip, Config as MpiConfig, Queries as MpiQueries};
// use random_linear_combination::{Chip as RlcChip, Config as RlcConfig, Queries as RlcQueries};
use std::{collections::HashMap, iter::once, marker::PhantomData};
use zksync_crypto::params::ACCOUNT_TREE_DEPTH;

const N_LIMBS_RW_COUNTER: usize = 2;
const N_LIMBS_ACCOUNT_ADDRESS: usize = 10;
const N_LIMBS_ID: usize = 2;
const N_LIMBS_INDEX: usize = 5;
/// The MptTable shared between MPT Circuit and State Circuit
#[derive(Clone, Copy, Debug)]
pub struct AccountTreeTable([Column<Advice>; 7]);
impl DynamicTableColumns for AccountTreeTable {
    fn columns(&self) -> Vec<Column<Advice>> {
        self.0.to_vec()
    }
}

impl AccountTreeTable {
    /// Construct a new MptTable
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self([0; 7].map(|_| meta.advice_column()))
    }

    pub(crate) fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &(Fr, bool),
    ) -> Result<(), Error> {
        // for (column, value) in self.0.iter().zip_eq(row.values()) {
        //     region.assign_advice(|| "assign mpt table row value", *column, offset, || *value)?;
        // }

        Ok(())
    }

    pub(crate) fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        updates: &MptUpdates,
        randomness: Value<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "account tree table",
            |mut region| self.load_with_region(&mut region, updates, randomness),
        )
    }

    pub fn load_account_tree_with_region<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        merkle_path: &Vec<(Fr, bool)>,
    ) -> Result<(), Error> {
        for (offset, row) in merkle_path.iter().enumerate() {
            self.assign(region, offset, row)?;
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct MerkleCircuitConfig<F: Field> {
    // // Figure out why you get errors when this is Selector.
    //selector: Column<Fixed>,
    // rw_table: RwTable,
    // sort_keys: SortKeysConfig,
    // // Assigned value at the start of the block. For Rw::Account and
    // // Rw::AccountStorage rows this is the committed value in the MPT, for
    // // others, it is 0.
    // initial_value: Column<Advice>,
    // // For Rw::AccountStorage, identify non-existing if both committed value and
    // // new value are zero. Will do lookup for ProofType::StorageDoesNotExist if
    // // non-existing, otherwise do lookup for ProofType::StorageChanged.
    // // TODO: use BatchedIsZeroGadget here, once it doesn't depend on the evm circuit constraint
    // // builder.
    // is_non_exist: Column<Advice>,
    state_root: Column<Advice>,
    // lexicographic_ordering: LexicographicOrderingConfig,
    // not_first_access: Column<Advice>,
    // lookups: LookupsConfig,
    power_of_randomness: [Expression<F>; N_BYTES_WORD - 1],
    // External tables
    mpt_table: MptTable,
    acc_tree_table: AccountTreeTable,
}
pub struct MerkleCircuitConfigArgs<F: Field> {
    /// RwTable
    pub rw_table: RwTable,
    /// MptTable
    pub mpt_table: MptTable,
    pub acc_tree_table: AccountTreeTable,
    /// Challenges
    pub power_of_randomness: [Expression<F>; N_BYTES_WORD - 1],
}

impl<F: Field> SubCircuitConfig<F> for MerkleCircuitConfig<F> {
    type ConfigArgs = MerkleCircuitConfigArgs<F>;

    /// Return a new StateCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            rw_table,
            mpt_table,
            power_of_randomness,
        }: Self::ConfigArgs,
    ) -> Self {
        let selector = meta.fixed_column();
        let state_root = meta.advice_column();
        let acc_tree_table = AccountTreeTable::construct(meta);
        let config = Self {
            //selector,
            // sort_keys,
            // initial_value,
            // is_non_exist,
            state_root,
            // lexicographic_ordering,
            // not_first_access: meta.advice_column(),
            // lookups,
            power_of_randomness,
            // rw_table,
            mpt_table,
            acc_tree_table,
        };
        meta.create_gate("state circuit constraints", |meta| {
            let s = meta.query_selector(s_add);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * (a + b - c)]
        });
        for (name, lookup) in constraint_builder.lookups() {
            let ind = meta.lookup_any(name, |_| lookup);
            println!("State circuit add lookup {} to CS at index {}", name, ind);
        }
        config
    }
}
impl<F: Field> MerkleCircuitConfig<F> {
    /// Make the assignments to the StateCircuit
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        rows: &[Rw],
        n_rows: usize, // 0 means dynamically calculated from `rows`.
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let updates = MptUpdates::from(rows);
        layouter.assign_region(
            || "merkle circuit",
            |mut region| {
                self.assign_with_region(&mut region, rows, &updates, n_rows, challenges.evm_word())
            },
        )
    }
    fn assign_account_tree_with_region(
        &self,
        region: &mut Region<'_, F>,
        merkle_paths: &Vec<(Fr, bool)>,
    ) -> Result<(), Error> {
        Ok(())
    }
    fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        rows: &[Rw],
        updates: &MptUpdates,
        n_rows: usize, // 0 means dynamically calculated from `rows`.
        randomness: Value<F>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Default, Clone, Debug)]
pub struct MerkleCircuit<F: Field> {
    /// Rw rows
    pub rows: Vec<Rw>,
    updates: MptUpdates,
    pub(crate) n_rows: usize,
    //leaf: Value<F>,
    leaf_pos: Value<u32>,
    merkle_path: Vec<(crate::Fr, bool)>,
    // #[cfg(test)]
    // overrides: HashMap<(test::AdviceColumn, isize), F>,
    _marker: PhantomData<F>,
}
impl<F: Field> MerkleCircuit<F> {
    /// make a new state circuit from an RwMap
    pub fn new(rw_map: RwMap, n_rows: usize) -> Self {
        let rows = rw_map.table_assignments();
        let updates = MptUpdates::from(&rows);
        //println!("State update {:?}", updates);
        Self {
            rows,
            updates,
            n_rows,
            leaf_pos: Value::unknown(),
            merkle_path: Vec::default(),
            _marker: PhantomData::default(),
        }
    }
    pub fn assign_account_tree(&mut self, account_tree: &AccountTree, account_pos: u32) {
        println!("ASSIGN ACCOUNT TREE pos {:?}", account_pos);
        if let Some(account) = account_tree.get(account_pos) {
            self.leaf_pos = Value::known(account_pos);
            //self.leaf = Value::known(account_tree.hasher.hash_elements(account));
            self.merkle_path = account_tree.merkle_path(account_pos);
            println!("Merkle path {:?}", &self.merkle_path);
        }
    }
}
impl<F: Field> SubCircuit<F> for MerkleCircuit<F> {
    type Config = MerkleCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        let circuit = Self::new(block.rws.clone(), block.circuits_params.max_rws);
        circuit
    }
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        (0, 0)
    }

    /// Make the assignments to the MerkleCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let randomness = challenges.evm_word();
        layouter.assign_region(
            || "merkle subcircuit",
            |mut region| {
                // match config
                //     .mpt_table
                //     .load_with_region(&mut region, &self.updates, randomness)
                // {
                //     Err(err) => {
                //         panic!("MptTable load_with_region error {:?}", &err);
                //         //return Err(err);
                //     }
                //     _ => {}
                // };
                config
                    .acc_tree_table
                    .load_account_tree_with_region(&mut region, &self.merkle_path)?;
                match config.assign_with_region(
                    &mut region,
                    &self.rows,
                    &self.updates,
                    self.n_rows,
                    randomness,
                ) {
                    Err(err) => {
                        panic!("Config assign_with_region error {:?}", &err);
                        //return Err(err);
                    }
                    _ => {}
                };
                Ok(())
            },
        );
        Ok(())
    }
}

#[cfg(any(feature = "test", test))]
impl<F: Field> Circuit<F> for MerkleCircuit<F>
where
    F: Field,
{
    type Config = (MerkleCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let rw_table = RwTable::construct(meta);
        let mpt_table = MptTable::construct(meta);
        let acc_tree_table = AccountTreeTable::construct(meta);
        let challenges = Challenges::construct(meta);

        let config = {
            let challenges = challenges.exprs(meta);
            MerkleCircuitConfig::new(
                meta,
                MerkleCircuitConfigArgs {
                    rw_table,
                    mpt_table,
                    acc_tree_table,
                    power_of_randomness: challenges.evm_word_powers_of_randomness(),
                },
            )
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&mut layouter);
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}
