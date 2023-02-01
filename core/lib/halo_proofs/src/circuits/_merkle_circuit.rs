use eth_types::Field;
use halo2_proofs::circuit::{SimpleFloorPlanner, Value};
use halo2_proofs::halo2curves::bn256::Fr;
const MERKLE_DEPTH: usize = 32;
use crate::chips::{MerkleKeccakChip, MerkleKeccakConfig, MerklePath};
use halo2_gadgets::utilities::{cond_swap::CondSwapInstructions, i2lebsp, UtilitiesInstructions};
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use rand_core::{OsRng, RngCore};
use tracing::info;
use tracing_test::traced_test;
use zkevm_circuits::keccak_circuit::keccak_packed_multi::{
    KeccakCircuitConfig, KeccakCircuitConfigArgs,
};
use zkevm_circuits::keccak_circuit::KeccakConfig;
use zkevm_circuits::table::KeccakTable;
use zkevm_circuits::util::{Challenges, SubCircuitConfig};

#[cfg(test)]
#[derive(Default)]
struct MerkleCircuit<F: Field> {
    leaf: Value<F>,
    leaf_pos: Value<u32>,
    merkle_path: Value<[F; MERKLE_DEPTH]>,
}
impl<F: Field> Circuit<F> for MerkleCircuit<F> {
    type Config = MerkleKeccakConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let config = MerkleKeccakChip::configure(meta);
        config
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // Load generator table (shared across both configs)
        //MerkleKeccakChip::load(config.0.sinsemilla_config.clone(), &mut layouter)?;

        // Construct Merkle chips which will be placed side-by-side in the circuit.
        let chip = MerkleKeccakChip::construct(config.clone());
        //Load single private witness from halo2_gadgets::utilities::UtilitiesInstructions
        let leaf = chip.load_private(
            layouter.namespace(|| ""),
            config.cond_swap_config.a(),
            self.leaf,
        )?;

        let path = MerklePath {
            chips: [chip],
            leaf_pos: self.leaf_pos,
            path: self.merkle_path,
        };
        let computed_final_root =
            path.calculate_root(layouter.namespace(|| "calculate root"), leaf)?;
        /*
        self.leaf
            .zip(self.leaf_pos)
            .zip(self.merkle_path)
            .zip(computed_final_root.value())
            .assert_if_known(|(((leaf, leaf_pos), merkle_path), computed_final_root)| {
                // The expected final root
                let final_root =
                    merkle_path
                        .iter()
                        .enumerate()
                        .fold(*leaf, |node, (l, sibling)| {
                            let l = l as u8;
                            let (left, right) = if leaf_pos & (1 << l) == 0 {
                                (&node, sibling)
                            } else {
                                (sibling, &node)
                            };

                            use crate::sinsemilla::primitives as sinsemilla;
                            let merkle_crh =
                                sinsemilla::HashDomain::from_Q(TestHashDomain.Q().into());

                            merkle_crh
                                .hash(
                                    iter::empty()
                                        .chain(i2lebsp::<10>(l as u64).iter().copied())
                                        .chain(
                                            left.to_le_bits()
                                                .iter()
                                                .by_vals()
                                                .take(pallas::Base::NUM_BITS as usize),
                                        )
                                        .chain(
                                            right
                                                .to_le_bits()
                                                .iter()
                                                .by_vals()
                                                .take(pallas::Base::NUM_BITS as usize),
                                        ),
                                )
                                .unwrap_or(pallas::Base::zero())
                        });

                // Check the computed final root against the expected final root.
                computed_final_root == &&final_root
            });
             */
        Ok(())
    }
}
#[tokio::test]
async fn test_merkle_circuit() {
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    let mut rng = OsRng;

    // Choose a random leaf and position
    let leaf = Fr::random(rng);
    let pos = rng.next_u32();

    // Choose a path of random inner nodes
    let path: Vec<_> = (0..(MERKLE_DEPTH)).map(|_| Fr::random(rng)).collect();

    // The root is provided as a public input in the Orchard circuit.

    let circuit = MerkleCircuit::<Fr> {
        leaf: Value::known(leaf),
        leaf_pos: Value::known(pos),
        merkle_path: Value::known(path.try_into().unwrap()),
    };

    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()))
}
