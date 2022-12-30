use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::Error;

pub mod deposit;

pub trait Transaction<F: FieldExt> {
    fn load_input_transaction(&self, layouter: impl Layouter<F>) -> Result<(), Error>;
    fn execute(&self, layouter: impl Layouter<F>) -> Result<(), Error>;
}
pub use deposit::DepositTran;
