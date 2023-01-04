use crate::instructions::DepositInstructions;
use crate::state::State;
use crate::transactions::Transaction;
use halo2_proofs::circuit::{Chip, Layouter};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector};
use halo2_proofs::{arithmetic::FieldExt, plonk::Instance};
use std::marker::PhantomData;

/// Configuration for the `DepositChip` implementation.
/// The constraint system matrix for an arity-2 Merkle tree of 8 leaves using a mocked hasher (one
// selector/gate `s_hash` and one allocation `digest = (l + GAMMA) * (r + GAMMA)` for a random
// gamma and Merkle left/right inputs `l` and `r`).

// |-----||------------------|------------------|----------|---------|-------|---------|--------|--------|
// | row ||       a_col      |       b_col      |  c_col   | pub_col | s_pub | s_bool  | s_swap | s_hash |
// |-----||------------------|------------------|----------|---------|-------|---------|--------|--------|
// |  0  ||       leaf       |      elem_1      |  cbit_1  | cbit_1  |   1   |    1    |    1   |    0   |
// |  1  ||    leaf/elem_1   |   leaf/elem_1    | digest_1 |         |   0   |    0    |    0   |    1   |
// |  2  ||     digest_1*    |      elem_2      |  cbit_2  | cbit_2  |   1   |    1    |    1   |    0   |
// |  3  || digest_1/elem_2  | digest_1/elem_2  | digest_2 |         |   0   |    0    |    0   |    1   |
// |  4  ||     digest_2*    |       elem_3     |  cbit_3  | cbit_3  |   1   |    1    |    1   |    0   |
// |  5  || digest_2/elem_3  | digest_2/elem_3  | digest_3 |  root   |   1   |    0    |    0   |    1   |
// |-----||------------------|------------------|----------|---------|-------|---------|--------|--------|
//   "*" = copy
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositConfig {
    //Public columns: contains merkle tree path
    instance: Column<Instance>,
    advices: [Column<Advice>; 3],
    selectors: [Selector; 4],
    fixed: Column<Fixed>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositChip<F: FieldExt> {
    config: DepositConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for DepositChip<F> {
    type Config = DepositConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> DepositChip<F> {
    pub fn construct(config: DepositConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }
    /// Configures the [`DepositChip`].
    pub fn configure(meta: &mut ConstraintSystem<F>) -> DepositConfig {
        // We also need an instance column to store public inputs.
        let instance = meta.instance_column();
        // We create the two advice columns that FieldChip uses for I/O.
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        //Create the 4 selectors
        let selectors = [
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
        ];
        // Create a fixed column to load constants.
        let fixed = meta.fixed_column();
        DepositConfig {
            instance,
            advices,
            selectors,
            fixed,
        }
    }
}

impl<F: FieldExt> DepositInstructions<F> for DepositChip<F> {
    fn load_transaction<Tran: Transaction<F>>(
        &self,
        layouter: impl Layouter<F>,
        tran: &Tran,
    ) -> Result<(), Error> {
        tran.load_input_transaction(layouter)
    }

    fn load_state<S: State<F>>(&self, layouter: impl Layouter<F>, state: &S) -> Result<(), Error> {
        /*
        layouter.assign_region(
            || "Load state",
            |mut region| {
                region
                    .assign_advice(|| "private input", config.advice[0], 0, || value)
                    .map(Number)
            },
        );
        */
        Ok(())
    }
    fn load_constant(&self, layouter: impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
    fn execute<Tran: Transaction<F>>(
        &self,
        layouter: impl Layouter<F>,
        tran: &Tran,
    ) -> Result<(), Error> {
        tran.execute(layouter)
    }
    //Re
    fn expose_public(&self, layouter: impl Layouter<F>, row: usize) -> Result<(), Error> {
        let config = self.config();

        //layouter.constrain_instance(num.0.cell(), config.instance, row)
        Ok(())
    }
}
