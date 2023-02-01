#![allow(missing_docs)]
pub mod param;
pub mod step;
pub mod table;
pub mod util;
use crate::table::{BlockTable, BytecodeTable, CopyTable, ExpTable, KeccakTable, RwTable, TxTable};
use crate::util::{Challenges, SubCircuit, SubCircuitConfig};
use crate::witness::Block;
use eth_types::{Address, Field};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::*,
};
use itertools::Itertools;
use strum::IntoEnumIterator;
use table::FixedTableTag;

/// EvmCircuitConfig implements verification of execution trace of a block.
#[derive(Clone, Debug)]
pub struct EvmCircuitConfig {
    fixed_table: [Column<Fixed>; 4],
    byte_table: [Column<Fixed>; 1],
    //pub(crate) execution: Box<ExecutionConfig<F>>,
    // External tables
    tx_table: TxTable,
    rw_table: RwTable,
    bytecode_table: BytecodeTable,
    block_table: BlockTable,
    copy_table: CopyTable,
    keccak_table: KeccakTable,
    exp_table: ExpTable,
}

/// Circuit configuration arguments
pub struct EvmCircuitConfigArgs<F: Field> {
    /// Power of randomness
    pub power_of_randomness: [Expression<F>; 31],
    /// TxTable
    pub tx_table: TxTable,
    /// RwTable
    pub rw_table: RwTable,
    /// BytecodeTable
    pub bytecode_table: BytecodeTable,
    /// BlockTable
    pub block_table: BlockTable,
    /// CopyTable
    pub copy_table: CopyTable,
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// ExpTable
    pub exp_table: ExpTable,
}

impl<F: Field> SubCircuitConfig<F> for EvmCircuitConfig {
    type ConfigArgs = EvmCircuitConfigArgs<F>;

    /// Configure EvmCircuitConfig
    #[allow(clippy::too_many_arguments)]
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            power_of_randomness,
            tx_table,
            rw_table,
            bytecode_table,
            block_table,
            copy_table,
            keccak_table,
            exp_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let fixed_table = [(); 4].map(|_| meta.fixed_column());
        let byte_table = [(); 1].map(|_| meta.fixed_column());
        /*
        let execution = Box::new(ExecutionConfig::configure(
            meta,
            power_of_randomness,
            &fixed_table,
            &byte_table,
            &tx_table,
            &rw_table,
            &bytecode_table,
            &block_table,
            &copy_table,
            &keccak_table,
            &exp_table,
        ));
        */
        Self {
            fixed_table,
            byte_table,
            //execution,
            tx_table,
            rw_table,
            bytecode_table,
            block_table,
            copy_table,
            keccak_table,
            exp_table,
        }
    }
}

impl EvmCircuitConfig {
    pub fn get_num_rows_required<F: Field>(&self, block: &Block<F>) -> usize {
        // Start at 1 so we can be sure there is an unused `next` row available
        let mut num_rows = 1;
        let evm_rows = block.evm_circuit_pad_to;
        if evm_rows == 0 {
            for transaction in &block.txs {
                for step in &transaction.steps {
                    //num_rows += self.execution.get_step_height(step.execution_state);
                    num_rows += 1;
                }
            }
            num_rows += 1; // EndBlock
        } else {
            num_rows += block.evm_circuit_pad_to;
        }
        num_rows
    }
}
// Evm Circuit for verifying transaction signatures
#[derive(Clone, Default, Debug)]
pub struct EvmCircuit<F: Field> {
    /// Block
    pub block: Option<Block<F>>,
    fixed_table_tags: Vec<FixedTableTag>,
}

impl<F: Field> EvmCircuit<F> {
    /// Return a new EvmCircuit
    pub fn new(block: Block<F>) -> Self {
        Self {
            block: Some(block),
            fixed_table_tags: FixedTableTag::iter().collect(),
        }
    }

    pub fn new_dev(block: Block<F>, fixed_table_tags: Vec<FixedTableTag>) -> Self {
        Self {
            block: Some(block),
            fixed_table_tags,
        }
    }
}

impl<F: Field> SubCircuit<F> for EvmCircuit<F> {
    type Config = EvmCircuitConfig;

    fn new_from_block(block: &Block<F>) -> Self {
        Self::new(block.clone())
    }
    // Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &Block<F>) -> (usize, usize) {
        // let num_rows_required_for_execution_steps: usize =
        //     EvmCircuit::<F>::get_num_rows_required(block);
        let num_rows_required_for_execution_steps = 0;
        let num_rows_required_for_fixed_table: usize = detect_fixed_table_tags(block)
            .iter()
            .map(|tag| tag.build::<F>().count())
            .sum();
        (
            std::cmp::max(
                num_rows_required_for_execution_steps,
                num_rows_required_for_fixed_table,
            ),
            block.evm_circuit_pad_to,
        )
    }
    /// Make the assignments to the EvmCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        _challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let block = self.block.as_ref().unwrap();

        //config.load_fixed_table(layouter, self.fixed_table_tags.clone())?;
        //config.load_byte_table(layouter)?;
        //config.execution.assign_block(layouter, block)
        Ok(())
    }
}

// /// create fixed_table_tags needed given witness block
// pub(crate) fn _detect_fixed_table_tags<F: Field>(block: &Block<F>) -> Vec<FixedTableTag> {
//     let need_bitwise_lookup = block.txs.iter().any(|tx| {
//         tx.steps.iter().any(|step| {
//             matches!(
//                 step.opcode,
//                 Some(OpcodeId::AND)
//                     | Some(OpcodeId::OR)
//                     | Some(OpcodeId::XOR)
//                     | Some(OpcodeId::NOT)
//             )
//         })
//     });
//     FixedTableTag::iter()
//         .filter(|t| {
//             !matches!(
//                 t,
//                 FixedTableTag::BitwiseAnd | FixedTableTag::BitwiseOr | FixedTableTag::BitwiseXor
//             ) || need_bitwise_lookup
//         })
//         .collect()
// }
/// create fixed_table_tags needed given witness block
pub(crate) fn detect_fixed_table_tags<F: Field>(block: &Block<F>) -> Vec<FixedTableTag> {
    FixedTableTag::iter().collect()
}
#[cfg(any(feature = "test", test))]
pub mod test {}