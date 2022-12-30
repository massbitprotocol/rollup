#[cfg(test)]
mod test {
    use super::*;
    use crate::group_hash::BlakeHasher;
    use crate::rescue;
    use ::circuit::test::*;
    use bellman::pairing::bn256::{Bn256, Fr};
    use bellman::pairing::ff::PrimeField;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn test_rescue_mimc_gadget() {
        use crate::rescue::bn256::*;
        let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = Bn256RescueParams::new_2_into_1::<BlakeHasher>();
        let input: Vec<Fr> = (0..params.state_width()).map(|_| rng.gen()).collect();
        let expected = rescue::rescue_mimc::<Bn256>(&params, &input[..]);

        {
            let mut cs = TestConstraintSystem::<Bn256>::new();

            let input_words: Vec<Num<Bn256>> = input
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    let v = AllocatedNum::alloc(cs.namespace(|| format!("input {}", i)), || Ok(*b))
                        .unwrap();

                    Num::<Bn256>::from(v)
                })
                .collect();

            let res = rescue_mimc_over_lcs(cs.namespace(|| "rescue mimc"), &input_words, &params)
                .unwrap();

            let unsatisfied = cs.which_is_unsatisfied();
            if let Some(s) = unsatisfied {
                println!("Unsatisfied at {}", s);
            }

            assert!(cs.is_satisfied());
            assert!(res.len() == (params.state_width() as usize));

            assert_eq!(res[0].get_value().unwrap(), expected[0]);
        }
    }

    #[test]
    fn test_rescue_hash_gadget() {
        use crate::rescue::bn256::*;
        let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = Bn256RescueParams::new_2_into_1::<BlakeHasher>();
        // let input: Vec<Fr> = (0..(params.rate()*2)).map(|_| rng.gen()).collect();
        let input: Vec<Fr> = (0..params.rate()).map(|_| rng.gen()).collect();
        let expected = rescue::rescue_hash::<Bn256>(&params, &input[..]);

        {
            let mut cs = TestConstraintSystem::<Bn256>::new();

            let input_words: Vec<AllocatedNum<Bn256>> = input
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    AllocatedNum::alloc(cs.namespace(|| format!("input {}", i)), || Ok(*b)).unwrap()
                })
                .collect();

            let res = rescue_hash(cs.namespace(|| "rescue hash"), &input_words, &params).unwrap();

            assert!(cs.is_satisfied());
            assert!(res.len() == 1);
            println!(
                "Rescue hash {} to {} taken {} constraints",
                input.len(),
                res.len(),
                cs.num_constraints()
            );

            assert_eq!(res[0].get_value().unwrap(), expected[0]);
        }
    }

    #[test]
    fn test_rescue_hash_long_gadget() {
        use crate::rescue::bn256::*;
        let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = Bn256RescueParams::new_2_into_1::<BlakeHasher>();
        let input: Vec<Fr> = (0..(params.rate() * 5)).map(|_| rng.gen()).collect();
        let expected = rescue::rescue_hash::<Bn256>(&params, &input[..]);

        {
            let mut cs = TestConstraintSystem::<Bn256>::new();

            let input_words: Vec<AllocatedNum<Bn256>> = input
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    AllocatedNum::alloc(cs.namespace(|| format!("input {}", i)), || Ok(*b)).unwrap()
                })
                .collect();

            let res = rescue_hash(cs.namespace(|| "rescue hash"), &input_words, &params).unwrap();

            assert!(cs.is_satisfied());
            assert!(res.len() == 1);
            println!(
                "Rescue hash {} to {} taken {} constraints",
                input.len(),
                res.len(),
                cs.num_constraints()
            );

            assert_eq!(res[0].get_value().unwrap(), expected[0]);
        }
    }

    #[test]
    fn test_rescue_hash_stateful_gadget() {
        use crate::rescue::bn256::*;
        let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = Bn256RescueParams::new_2_into_1::<BlakeHasher>();
        // let input: Vec<Fr> = (0..(params.rate()*2)).map(|_| rng.gen()).collect();
        let input: Vec<Fr> = (0..(params.rate() + 1)).map(|_| rng.gen()).collect();
        let expected = rescue::rescue_hash::<Bn256>(&params, &input[..]);

        {
            let mut cs = TestConstraintSystem::<Bn256>::new();

            let input_words: Vec<AllocatedNum<Bn256>> = input
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    AllocatedNum::alloc(cs.namespace(|| format!("input {}", i)), || Ok(*b)).unwrap()
                })
                .collect();

            let res = rescue_hash(cs.namespace(|| "rescue hash"), &input_words, &params).unwrap();

            assert!(cs.is_satisfied());
            assert!(res.len() == 1);

            println!(
                "Rescue stateless hash {} to {} taken {} constraints",
                input.len(),
                res.len(),
                cs.num_constraints()
            );

            let constr = cs.num_constraints();

            let mut rescue_gadget = StatefulRescueGadget::<Bn256>::new(&params);

            rescue_gadget.specialize(
                cs.namespace(|| "specialize rescue hash"),
                input_words.len() as u8,
            );

            rescue_gadget
                .absorb(
                    cs.namespace(|| "absorb the input into stateful rescue gadget"),
                    &input_words,
                    &params,
                )
                .unwrap();

            let res_0 = rescue_gadget
                .squeeze_out_single(cs.namespace(|| "squeeze first word"), &params)
                .unwrap();

            assert_eq!(res_0.get_value().unwrap(), expected[0]);
            println!(
                "Rescue stateful hash {} to {} taken {} constraints",
                input.len(),
                res.len(),
                cs.num_constraints() - constr
            );

            let res_1 = rescue_gadget
                .squeeze_out_single(cs.namespace(|| "squeeze second word"), &params)
                .unwrap();

            let mut stateful_hasher = rescue::StatefulRescue::<Bn256>::new(&params);
            stateful_hasher.specialize(input.len() as u8);

            stateful_hasher.absorb(&input);

            let r0 = stateful_hasher.squeeze_out_single();
            let r1 = stateful_hasher.squeeze_out_single();

            assert_eq!(res_0.get_value().unwrap(), r0);
            assert_eq!(res_1.get_value().unwrap(), r1);
        }
    }

    #[test]
    fn test_rescue_hash_gadget_3_into_1() {
        use crate::rescue::bn256::*;
        let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = Bn256RescueParams::new_3_into_1::<BlakeHasher>();
        // let input: Vec<Fr> = (0..(params.rate()*2)).map(|_| rng.gen()).collect();
        let input: Vec<Fr> = (0..params.rate()).map(|_| rng.gen()).collect();
        let expected = rescue::rescue_hash::<Bn256>(&params, &input[..]);

        {
            let mut cs = TestConstraintSystem::<Bn256>::new();

            let input_words: Vec<AllocatedNum<Bn256>> = input
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    AllocatedNum::alloc(cs.namespace(|| format!("input {}", i)), || Ok(*b)).unwrap()
                })
                .collect();

            let res = rescue_hash(cs.namespace(|| "rescue hash"), &input_words, &params).unwrap();

            assert!(cs.is_satisfied());
            assert!(res.len() == 1);
            println!(
                "Rescue hash {} to {} taken {} constraints",
                input.len(),
                res.len(),
                cs.num_constraints()
            );

            assert_eq!(res[0].get_value().unwrap(), expected[0]);
        }
    }

    #[test]
    fn test_transpile_rescue_hash_gadget() {
        use crate::rescue::bn256::*;
        let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = Bn256RescueParams::new_2_into_1::<BlakeHasher>();
        // let input: Vec<Fr> = (0..(params.rate()*2)).map(|_| rng.gen()).collect();
        let input: Vec<Fr> = (0..params.rate()).map(|_| rng.gen()).collect();
        let expected = rescue::rescue_hash::<Bn256>(&params, &input[..]);

        #[derive(Clone)]
        struct RescueTester<E: RescueEngine> {
            num_duplicates: usize,
            input: Vec<E::Fr>,
            params: E::Params,
        }

        impl<E: RescueEngine> crate::bellman::Circuit<E> for RescueTester<E>
        where
            <<E as RescueEngine>::Params as RescueHashParams<E>>::SBox0: CsSBox<E>,
            <<E as RescueEngine>::Params as RescueHashParams<E>>::SBox1: CsSBox<E>,
        {
            fn synthesize<CS: ConstraintSystem<E>>(
                self,
                cs: &mut CS,
            ) -> Result<(), SynthesisError> {
                for _ in 0..self.num_duplicates {
                    let mut input_words = vec![];
                    for (i, inp) in self.input.iter().enumerate() {
                        let v = AllocatedNum::alloc(
                            cs.namespace(|| format!("hash input {}", i)),
                            || Ok(*inp),
                        )?;

                        input_words.push(v);
                    }

                    let mut res =
                        rescue_hash(cs.namespace(|| "rescue hash"), &input_words, &self.params)?;

                    let res = res.pop().unwrap();

                    res.inputize(cs.namespace(|| "make input"))?;
                }

                Ok(())
            }
        }

        use crate::bellman::plonk::*;
        use crate::bellman::worker::Worker;

        // let mut transpiler = Transpiler::new();

        let dupls: usize = 1024;

        let c = RescueTester::<Bn256> {
            num_duplicates: dupls,
            input: input,
            params: params,
        };

        let (n, hints) =
            transpile_with_gates_count::<Bn256, _>(c.clone()).expect("transpilation is successful");

        let mut hints_hist = std::collections::HashMap::new();
        hints_hist.insert("into addition gate".to_owned(), 0);
        hints_hist.insert("merge LC".to_owned(), 0);
        hints_hist.insert("into quadratic gate".to_owned(), 0);
        hints_hist.insert("into multiplication gate".to_owned(), 0);

        use crate::bellman::plonk::better_cs::adaptor::TranspilationVariant;

        for (_, h) in hints.iter() {
            match h {
                TranspilationVariant::IntoQuadraticGate => {
                    *hints_hist
                        .get_mut(&"into quadratic gate".to_owned())
                        .unwrap() += 1;
                }
                TranspilationVariant::MergeLinearCombinations(..) => {
                    *hints_hist.get_mut(&"merge LC".to_owned()).unwrap() += 1;
                }
                TranspilationVariant::IntoAdditionGate(..) => {
                    *hints_hist
                        .get_mut(&"into addition gate".to_owned())
                        .unwrap() += 1;
                }
                TranspilationVariant::IntoMultiplicationGate(..) => {
                    *hints_hist
                        .get_mut(&"into multiplication gate".to_owned())
                        .unwrap() += 1;
                }
            }
        }

        println!("Transpilation hist = {:?}", hints_hist);

        println!("Done transpiling");

        println!("Made {} invocations into {} gates", dupls, n);
    }
}
