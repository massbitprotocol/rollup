RUST_BACKTRACE=1 DEGREE=10 cargo +nightly test --package halo_proofs --lib --
circuits::simplified_circuit::simplified_circuit_tests::serial_test_simplified_circuit --exact --nocapture --show-output
--ignored cargo +nightly test --package halo_proofs --lib --
circuits::keccak_circuit::keccak_packed_multi::tests::packed_multi_keccak_simple --exact --nocapture --show-output
--ignored
