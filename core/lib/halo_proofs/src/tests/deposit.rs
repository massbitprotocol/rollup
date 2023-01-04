use zksync_basic_types::{AccountId, BlockNumber, TokenId};
use zksync_circuit::witness::WitnessBuilder;
use zksync_types::{Deposit, DepositOp};

use crate::{
    circuits::deposit::DepositCircuit,
    tests::{account::WitnessTestAccount, utils},
};
use num::BigUint;
use tracing::info;
use tracing_test::traced_test;

const MERKLE_DEPTH: usize = 30;

#[tokio::test]
#[traced_test]
async fn test_deposit_circuit() {
    use halo2_proofs::dev::MockProver;
    let k = 4;
    let account = WitnessTestAccount::new_empty(AccountId(1));
    let deposit_to_account_id = account.id;
    let deposit_to_account_address = account.account.address;
    let (mut plasma_state, mut circuit_account_tree) =
        utils::RollupStateGenerator::generate(&vec![account]);
    let fee_account_id = AccountId(0);
    let mut witness_accum = WitnessBuilder::new(
        &mut circuit_account_tree,
        fee_account_id,
        BlockNumber(1),
        utils::BLOCK_TIMESTAMP,
    );
    info!("test_deposit_circuit");
    let deposit_op = DepositOp {
        priority_op: Deposit {
            from: deposit_to_account_address,
            token: TokenId(0),
            amount: BigUint::from(1u32),
            to: deposit_to_account_address,
        },
        account_id: deposit_to_account_id,
    };
    let deposit_circuit = DepositCircuit {
        leaf: Default::default(),
        leaf_pos: Default::default(),
        state: plasma_state,
        tran: Some(deposit_op),
        merkle_path: Default::default(),
    };
    // Arrange the public input. We expose the multiplication result in row 0
    // of the instance column, so we position it there in our public inputs.

    let public_inputs = vec![];

    // Given the correct public input, our circuit will verify.
    let prover = MockProver::run(k, &deposit_circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    // If we try some other public input, the proof will fail!
    //public_inputs[0] += Fp::one();
    //let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    //assert!(prover.verify().is_err());

    /*
    plasma_state.apply_deposit_op(&deposit_op);
    let deposit_witness = DepositWitness::apply_tx(witness_accum.account_tree, &deposit_op);
    let deposit_operations = deposit_witness.calculate_operations(());
    let pub_data_from_witness = deposit_witness.get_pubdata();

    witness_accum.add_operation_with_pubdata(deposit_operations, pub_data_from_witness);
    witness_accum.collect_fees(&Vec::new());
    witness_accum.calculate_pubdata_commitment();

    assert_eq!(
        plasma_state.root_hash(),
        witness_accum
            .root_after_fees
            .expect("witness accum after root hash empty"),
        "root hash in state keeper and witness generation code mismatch"
    );

    use zksync_crypto::franklin_crypto::bellman::pairing::bn256::Bn256;
    use zksync_crypto::franklin_crypto::bellman::plonk::adaptor::alternative::*;
    use zksync_crypto::franklin_crypto::bellman::plonk::plonk::generator::*;
    use zksync_crypto::franklin_crypto::bellman::plonk::plonk::prover::*;
    use zksync_crypto::franklin_crypto::bellman::Circuit;

    let mut transpiler = Transpiler::new();

    let c = witness_accum.into_circuit_instance();

    c.clone().synthesize(&mut transpiler).unwrap();

    println!("Done transpiling");

    let hints = transpiler.into_hints();

    use zksync_crypto::franklin_crypto::bellman::plonk::cs::Circuit as PlonkCircuit;

    let adapted_curcuit = Adaptorcircuit::new(c.clone(), &hints);

    let mut assembly = GeneratorAssembly::<Bn256>::new();
    adapted_curcuit.synthesize(&mut assembly).unwrap();
    assembly.finalize();

    println!("Transpiled into {} gates", assembly.num_gates());

    println!("Trying to prove");

    let adapted_curcuit = Adaptorcircuit::new(c.clone(), &hints);

    let mut prover = ProvingAssembly::<Bn256>::new();
    adapted_curcuit.synthesize(&mut prover).unwrap();
    prover.finalize();

    println!("Checking if is satisfied");
    assert!(prover.is_satisfied());
    */
}
