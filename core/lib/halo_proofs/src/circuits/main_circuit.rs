use super::{
    EvmCircuit, EvmCircuitConfig, EvmCircuitConfigArgs, PiCircuit, PiCircuitConfig,
    PiCircuitConfigArgs, StateCircuit, StateCircuitConfig, StateCircuitConfigArgs,
};
use bus_mapping::circuit_input_builder::{CircuitInputBuilder, CircuitsParams};
use bus_mapping::mock::BlockData;
use eth_types::{geth_types::GethData, Field};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error, Expression},
};

use super::evm_circuit::table::FixedTableTag;
use std::array;
use strum::IntoEnumIterator;
use zkevm_circuits::table::{
    BlockTable, BytecodeTable, CopyTable, ExpTable, KeccakTable, MptTable, RwTable, TxTable,
};
use zkevm_circuits::util::{Challenges, SubCircuit, SubCircuitConfig};
use zkevm_circuits::witness::{block_convert, Block, MptUpdates};

/// Mock randomness used for `SuperCircuit`.
pub const MOCK_RANDOMNESS: u64 = 0x100;
/// Configuration of the Main Circuit
#[derive(Clone)]
pub struct MainCircuitConfig<
    F: Field,
    const MAX_TXS: usize,
    const MAX_CALLDATA: usize,
    const MAX_RWS: usize,
> {
    block_table: BlockTable,
    mpt_table: MptTable,
    evm_circuit: EvmCircuitConfig,
    state_circuit: StateCircuitConfig<F>,
    pi_circuit: PiCircuitConfig<F>,
}

/// The Main Circuit contains all the zkEVM circuits
#[derive(Clone, Default, Debug)]
pub struct MainCircuit<
    F: Field,
    const MAX_TXS: usize,
    const MAX_CALLDATA: usize,
    const MAX_RWS: usize,
> {
    /// EVM Circuit
    pub evm_circuit: EvmCircuit<F>,
    /// State Circuit
    pub state_circuit: StateCircuit<F>,
    /// Public Input Circuit
    pub pi_circuit: PiCircuit<F>,
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize, const MAX_RWS: usize>
    MainCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_RWS>
{
    /// Return the number of rows required to verify a given block
    pub fn get_num_rows_required(block: &Block<F>) -> usize {
        let num_rows_evm_circuit = {
            let mut cs = ConstraintSystem::default();
            let config = Self::configure(&mut cs);
            config.evm_circuit.get_num_rows_required(block)
        };
        //let num_rows_tx_circuit = TxCircuitConfig::<F>::get_num_rows_required(MAX_TXS);
        //num_rows_evm_circuit.max(num_rows_tx_circuit)
        num_rows_evm_circuit.max(MAX_TXS)
    }
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize, const MAX_RWS: usize> Circuit<F>
    for MainCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_RWS>
{
    type Config = MainCircuitConfig<F, MAX_TXS, MAX_CALLDATA, MAX_RWS>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = TxTable::construct(meta);
        let rw_table = RwTable::construct(meta);
        let mpt_table = MptTable::construct(meta);
        let bytecode_table = BytecodeTable::construct(meta);
        let block_table = BlockTable::construct(meta);
        let q_copy_table = meta.fixed_column();
        let copy_table = CopyTable::construct(meta, q_copy_table);
        let exp_table = ExpTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let power_of_randomness: [Expression<F>; 31] = array::from_fn(|i| {
            Expression::Constant(F::from(MOCK_RANDOMNESS).pow(&[1 + i as u64, 0, 0, 0]))
        });
        let challenges = Challenges::mock(
            power_of_randomness[0].clone(),
            power_of_randomness[0].clone(),
        );
        let pi_circuit = PiCircuitConfig::new(
            meta,
            PiCircuitConfigArgs {
                max_txs: MAX_TXS,
                max_calldata: MAX_CALLDATA,
                block_table: block_table.clone(),
                tx_table: tx_table.clone(),
            },
        );
        let state_circuit = StateCircuitConfig::new(
            meta,
            StateCircuitConfigArgs {
                rw_table,
                mpt_table,
                challenges,
            },
        );
        let evm_circuit = EvmCircuitConfig::new(
            meta,
            EvmCircuitConfigArgs {
                power_of_randomness,
                tx_table,
                rw_table,
                bytecode_table,
                block_table: block_table.clone(),
                copy_table,
                keccak_table,
                exp_table,
            },
        );
        Self::Config {
            block_table,
            mpt_table,
            evm_circuit,
            state_circuit,
            pi_circuit,
        }
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let block = self.evm_circuit.block.as_ref().unwrap();
        let challenges = Challenges::mock(
            Value::known(block.randomness),
            Value::known(block.randomness),
        );
        // println!(
        //     "Main circuit synthesize with block params {:?}",
        //     block.circuits_params
        // );
        self.state_circuit
            .synthesize_sub(&config.state_circuit, &challenges, &mut layouter)?;
        self.evm_circuit
            .synthesize_sub(&config.evm_circuit, &challenges, &mut layouter)?;
        self.pi_circuit
            .synthesize_sub(&config.pi_circuit, &challenges, &mut layouter)?;
        //self.evm_circuit.synthesize(config.evm_circuit, layouter)?;
        Ok(())
    }
}

impl<const MAX_TXS: usize, const MAX_CALLDATA: usize, const MAX_RWS: usize>
    MainCircuit<Fr, MAX_TXS, MAX_CALLDATA, MAX_RWS>
{
    /// From the witness data, generate a SuperCircuit instance with all of the
    /// sub-circuits filled with their corresponding witnesses.
    ///
    /// Also, return with it the minimum required SRS degree for the
    /// circuit and the Public Inputs needed.
    #[allow(clippy::type_complexity)]
    pub fn build(
        geth_data: GethData,
    ) -> Result<(u32, Self, Vec<Vec<Fr>>, CircuitInputBuilder), bus_mapping::Error> {
        let block_data = BlockData::new_from_geth_data_with_params(
            geth_data.clone(),
            CircuitsParams {
                max_txs: MAX_TXS,
                max_calldata: MAX_CALLDATA,
                max_rws: MAX_RWS,
                max_bytecode: 512,
                keccak_padding: None,
            },
        );
        let mut builder = block_data.new_circuit_input_builder();
        builder
            .handle_block(&geth_data.eth_block, &geth_data.geth_traces)
            .expect("could not handle block tx");

        let ret = Self::build_from_circuit_input_builder(&builder)?;
        Ok((ret.0, ret.1, ret.2, builder))
    }
    /// From CircuitInputBuilder, generate a SuperCircuit instance with all of
    /// the sub-circuits filled with their corresponding witnesses.
    ///
    /// Also, return with it the minimum required SRS degree for the circuit and
    /// the Public Inputs needed.
    pub fn build_from_circuit_input_builder(
        builder: &CircuitInputBuilder,
    ) -> Result<(u32, Self, Vec<Vec<Fr>>), bus_mapping::Error> {
        let mut block = block_convert(&builder.block, &builder.code_db).unwrap();
        block.randomness = Fr::from(MOCK_RANDOMNESS);
        let fixed_table_tags: Vec<FixedTableTag> = FixedTableTag::iter().collect();
        let log2_ceil = |n| u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32;

        let num_rows_required =
            MainCircuit::<_, MAX_TXS, MAX_CALLDATA, MAX_RWS>::get_num_rows_required(&block);

        let k = log2_ceil(
            64 + fixed_table_tags
                .iter()
                .map(|tag| tag.build::<Fr>().count())
                .sum::<usize>(),
        );
        let bytecodes_len = block
            .bytecodes
            .iter()
            .map(|(_, bytecode)| bytecode.bytes.len())
            .sum::<usize>();
        let k = k.max(log2_ceil(64 + bytecodes_len));
        let k = k.max(log2_ceil(64 + num_rows_required));
        println!(
            "bytecodes len={}; num_rows_required={}; main circuit uses k = {}",
            bytecodes_len, num_rows_required, k
        );
        log::info!("main circuit uses k = {}", k);
        let evm_circuit = EvmCircuit::new_from_block(&block);
        let state_circuit = StateCircuit::new_from_block(&block);
        let pi_circuit = PiCircuit::new_from_block(&block);
        let circuit = MainCircuit::<_, MAX_TXS, MAX_CALLDATA, MAX_RWS> {
            evm_circuit,
            state_circuit,
            pi_circuit,
        };

        let instance = circuit.instance();
        Ok((k, circuit, instance))
    }
    pub fn instance(&self) -> Vec<Vec<Fr>> {
        // SignVerifyChip -> ECDSAChip -> MainGate instance column
        let pi_instance = self.pi_circuit.instance();
        //let instance = vec![pi_instance[0].clone(), vec![]];
        let instance = vec![pi_instance[0].clone()];
        instance
    }
}

#[cfg(test)]
mod main_circuit_tests {
    use super::*;
    use ark_std::{end_timer, start_timer};
    use eth_types::{address, bytecode, geth_types::GethData, Word};
    use ethers_signers::{LocalWallet, Signer};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
    use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
    use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
    use halo2_proofs::poly::kzg::strategy::SingleStrategy;
    use halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        poly::commitment::ParamsProver,
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    };
    use log::error;
    use mock::{TestContext, MOCK_CHAIN_ID};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use rand_xorshift::XorShiftRng;
    use std::collections::HashMap;
    use std::env::var;
    use std::slice;

    #[test]
    fn main_circuit_degree() {
        let mut cs = ConstraintSystem::<Fr>::default();
        MainCircuit::<_, 1, 32, 256>::configure(&mut cs);
        log::info!("super circuit degree: {}", cs.degree());
        log::info!("super circuit minimum_rows: {}", cs.minimum_rows());
        assert!(cs.degree() <= 9);
    }
    #[ignore]
    #[test]
    fn serial_test_main_circuit() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let degree: u32 = var("DEGREE")
            .expect("No DEGREE env var was provided")
            .parse()
            .expect("Cannot parse DEGREE env var as u32");
        let chain_id = (*MOCK_CHAIN_ID).as_u64();

        let bytecode = bytecode! {
            GAS
            STOP
        };

        let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

        let addr_a = wallet_a.address();
        let addr_b = address!("0x000000000000000000000000000000000000BBBB");

        let mut wallets = HashMap::new();
        wallets.insert(wallet_a.address(), wallet_a);

        let mut block: GethData = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(addr_b)
                    .balance(Word::from(1u64 << 20))
                    .code(bytecode);
                accs[1].address(addr_a).balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas(Word::from(1_000_000u64));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        block.sign(&wallets);

        let (k, circuit, instance, _) = MainCircuit::<_, 1, 32, 256>::build(block).unwrap();
        //Instance length must equals constraint.num_instance_column

        match MockProver::run(17, &circuit, instance.clone()) {
            Ok(prover) => {
                let res = prover.verify_par();
                if let Err(err) = res {
                    error!("Verification failures: {:#?}", err);
                    panic!("Failed verification");
                }
            }
            Err(err) => {
                panic!("MockProver run failed {:?}", &err);
            }
        }

        // Initialize the polynomial commitment parameters
        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        // Bench setup generation
        let setup_message = format!("Setup generation with degree = {}", degree);
        let start1 = start_timer!(|| setup_message);
        let general_params = ParamsKZG::<Bn256>::setup(degree, &mut rng);
        let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
        end_timer!(start1);
        // Initialize the proving key
        let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
        println!("Finish gen verification key");
        let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk should not fail");
        // Create a proof
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

        // Bench proof generation time
        let proof_message = format!("Main Circuit Proof generation with degree = {}", degree);
        //println!("Public instance: {:?}", &instance);
        //let instances: Vec<&[Fr]> = instance.iter().map(|v| v.as_slice()).collect();
        //let ref_instance = instance.iter().map(|elm| elm).collect::<Vec<&Fr>>();
        //let instances = instance.as_slice();
        let instances: Vec<&[Fr]> = instance.iter().map(|v| &v[..]).collect();
        let start2 = start_timer!(|| proof_message);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            XorShiftRng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            MainCircuit<Fr, 1, 32, 256>,
        >(
            &general_params,
            &pk,
            &[circuit],
            &[&instances],
            rng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        end_timer!(start2);
        println!("Proof size: {:?}", &proof.len());
        // Bench verification time
        let start3 = start_timer!(|| "Packed Multi-Keccak Proof verification");
        let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleStrategy::new(&general_params);

        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            &verifier_params,
            pk.get_vk(),
            strategy,
            &[&instances],
            &mut verifier_transcript,
        )
        .expect("failed to verify bench circuit");
        end_timer!(start3);
    }
}
