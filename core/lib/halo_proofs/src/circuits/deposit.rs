use crate::chips::deposit::{DepositChip, DepositConfig};
use crate::instructions::DepositInstructions;
use crate::state::RollupState;
use crate::Fp;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};
use zksync_types::DepositOp;
const MERKLE_DEPTH: usize = 30;

#[derive(Default, Debug, Clone)]
pub struct DepositCircuit {
    pub leaf: Value<Fp>,
    pub leaf_pos: Value<u32>,
    pub state: RollupState,
    pub tran: Option<DepositOp>,
    pub merkle_path: Value<[Fp; MERKLE_DEPTH]>,
}

impl Circuit<Fp> for DepositCircuit {
    type Config = DepositConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let config = DepositChip::<Fp>::configure(meta);
        config
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        println!("DepositCircuit synthesize");
        let chip = DepositChip::construct(config);

        chip.load_state(layouter.namespace(|| "load state"), &self.state)
            .expect("Load state error");

        chip.load_constant(layouter.namespace(|| "load constant"))
            .expect("Load constant error");
        if let Some(tran) = &self.tran {
            chip.load_transaction(layouter.namespace(|| "load transaction"), tran)
                .expect("load transaction error");
            chip.execute(layouter.namespace(|| "deposit execute"), tran)
                .expect("deposit execute");
        }
        chip.expose_public(layouter, 0)
            .expect("expose public error");
        Ok(())
    }
}
