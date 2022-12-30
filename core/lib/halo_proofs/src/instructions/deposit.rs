use crate::state::State;
use crate::transactions::Transaction;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{Chip, Layouter};
use halo2_proofs::plonk::Error;

pub trait DepositInstructions<F: FieldExt>: Chip<F> {
    fn load_transaction<Tran: Transaction<F>>(
        &self,
        layouter: impl Layouter<F>,
        tran: &Tran,
    ) -> Result<(), Error>;
    ///Load current L2 state into lookup tables
    /// State contain full account address list
    fn load_state<S: State<F>>(&self, layouter: impl Layouter<F>, state: &S) -> Result<(), Error>;

    fn load_constant(&self, layouter: impl Layouter<F>) -> Result<(), Error>;
    /// execute trasaction`.
    fn execute<Tran: Transaction<F>>(
        &self,
        layouter: impl Layouter<F>,
        tran: &Tran,
    ) -> Result<(), Error>;

    /// Exposes a new state as a public input to the circuit.
    fn expose_public(&self, layouter: impl Layouter<F>, row: usize) -> Result<(), Error>;
}
