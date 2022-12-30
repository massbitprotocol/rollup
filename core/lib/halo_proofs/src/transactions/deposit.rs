use halo2_proofs::{arithmetic::FieldExt, circuit::Value};
use zksync_types::DepositOp;

use super::Transaction;

#[derive(Debug, Clone)]
pub struct DepositTran<F: FieldExt> {
    value: Value<F>,
}

impl<F: FieldExt> Transaction<F> for DepositOp {
    fn load_input_transaction(
        &self,
        layouter: impl halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        println!("load_input_transaction");
        Ok(())
    }

    fn execute(
        &self,
        layouter: impl halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        println!("Execute transaction");
        Ok(())
    }
}
