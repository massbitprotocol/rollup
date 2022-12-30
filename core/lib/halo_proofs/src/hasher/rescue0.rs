//use super::super::rescue::*;
use super::num::{AllocatedNum, Num};
use crate::hasher::bn256::{PowerSBox, QuinticSBox, SBox};
use crate::hasher::rescue_hasher::RescueEngine;
use ff::{Field, PrimeField};
use halo2_proofs::plonk::Assignment;

//use bellman::pairing::Engine;
//use bellman::{ConstraintSystem, SynthesisError};
use halo2_proofs::halo2curves::{bn256, pairing::Engine};
use halo2_proofs::plonk::{
    Circuit, ConstraintSystem as Halo2ConstraintSystem, Error as PlonkError,
};
type SynthesisError = PlonkError;
pub trait ConstraintSystem<E: RescueEngine> {}
impl<E: RescueEngine> ConstraintSystem<E> for Halo2ConstraintSystem<E::Fr> {}
pub trait CsSBox<E: Engine>: SBox<E> {
    fn apply_constraints<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
        element: &AllocatedNum<E>,
    ) -> Result<AllocatedNum<E>, SynthesisError>;
    fn apply_constraints_on_lc<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
        element: Num<E>,
    ) -> Result<Num<E>, SynthesisError>;
    fn apply_constraints_for_set<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        elements: &[AllocatedNum<E>],
    ) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
        let mut results = Vec::with_capacity(elements.len());
        for (i, el) in elements.iter().enumerate() {
            let result =
                self.apply_constraints(cs.namespace(|| format!("apply sbox for word {}", i)), &el)?;

            results.push(result);
        }

        Ok(results)
    }

    fn apply_constraints_on_lc_for_set<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        elements: Vec<Num<E>>,
    ) -> Result<Vec<Num<E>>, SynthesisError> {
        let mut results = Vec::with_capacity(elements.len());
        for (i, el) in elements.into_iter().enumerate() {
            if el.is_empty() {
                results.push(el);
            } else {
                let applied = self.apply_constraints_on_lc(
                    cs.namespace(|| format!("actually apply sbox for word {}", i)),
                    el,
                )?;
                results.push(applied)
            }
        }

        Ok(results)
    }
}

impl<E: RescueEngine> CsSBox<E> for QuinticSBox<E> {
    fn apply_constraints<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        el: &AllocatedNum<E>,
    ) -> Result<AllocatedNum<E>, SynthesisError> {
        let sq = el.square(cs.namespace(|| "make 2nd power term"))?;

        let qd = sq.square(cs.namespace(|| "make 4th power term"))?;

        let res = el.mul(cs.namespace(|| "make 5th power term"), &qd)?;

        Ok(res)
    }

    fn apply_constraints_on_lc<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        el: Num<E>,
    ) -> Result<Num<E>, SynthesisError> {
        let sq = AllocatedNum::alloc(cs.namespace(|| "make 2nd power term"), || {
            let mut val = *el.get_value().get()?;
            val.square();

            Ok(val)
        })?;

        cs.enforce(
            || "enforce 2nd power term",
            |_| el.lc(E::Fr::one()),
            |_| el.lc(E::Fr::one()),
            |lc| lc + sq.get_variable(),
        );

        let qd = sq.square(cs.namespace(|| "make 4th power term"))?;

        let res = AllocatedNum::alloc(cs.namespace(|| "make 5th power term"), || {
            let mut val = *qd.get_value().get()?;
            let other = *el.get_value().get()?;
            val.mul_assign(&other);

            Ok(val)
        })?;

        cs.enforce(
            || "enforce 5th power term",
            |_| el.lc(E::Fr::one()),
            |lc| lc + qd.get_variable(),
            |lc| lc + res.get_variable(),
        );

        let res = Num::<E>::from(res);

        Ok(res)
    }
}

impl<E: Engine> CsSBox<E> for PowerSBox<E> {
    fn apply_constraints<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
        el: &AllocatedNum<E>,
    ) -> Result<AllocatedNum<E>, SynthesisError> {
        if self.inv == 5u64 {
            self.apply_constraints_inv_quint(cs, el)
        } else {
            unimplemented!()
        }
    }

    fn apply_constraints_on_lc<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
        el: Num<E>,
    ) -> Result<Num<E>, SynthesisError> {
        if self.inv == 5u64 {
            self.apply_constraints_inv_quint_on_lc(cs, el)
        } else {
            unimplemented!()
        }
    }
}

impl<E: Engine> PowerSBox<E> {
    fn apply_constraints_inv_quint<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        el: &AllocatedNum<E>,
    ) -> Result<AllocatedNum<E>, SynthesisError> {
        // we do powering and prove the inverse relationship
        let power = self.power;
        let f = AllocatedNum::alloc(cs.namespace(|| "allocate final state"), || {
            let v = *el.get_value().get()?;
            let s = v.pow(&power);

            Ok(s)
        })?;

        let dummy_quintic_box = QuinticSBox::<E> {
            _marker: std::marker::PhantomData,
        };
        let fifth = dummy_quintic_box
            .apply_constraints(cs.namespace(|| "apply quintic sbox for powering sbox"), &f)?;

        // // now constraint a chain that final^5 = state
        // let mut squares = Vec::with_capacity(state.len());
        // for (i, el) in final_states.iter().enumerate() {
        //     let sq = el.square(
        //         cs.namespace(|| format!("make 2nd power term for word {}", i))
        //     )?;
        //     squares.push(sq);
        // }

        // let mut quads = Vec::with_capacity(state.len());
        // for (i, el) in squares.iter().enumerate() {
        //     let qd = el.square(
        //         cs.namespace(|| format!("make 4th power term for word {}", i))
        //     )?;
        //     quads.push(qd);
        // }

        // let mut fifth = Vec::with_capacity(state.len());
        // for (i, (el, st)) in quads.iter().zip(final_states.iter()).enumerate() {
        //     let res = el.mul(
        //         cs.namespace(|| format!("make 5th power term for word {}", i)),
        //         &st
        //     )?;
        //     fifth.push(res);
        // }

        cs.enforce(
            || "enforce inverse box",
            |lc| lc + el.get_variable() - fifth.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );

        Ok(f)
    }

    fn apply_constraints_inv_quint_on_lc<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        el: Num<E>,
    ) -> Result<Num<E>, SynthesisError> {
        // we do powering and prove the inverse relationship
        let power = self.power;
        let f = AllocatedNum::alloc(cs.namespace(|| "allocate final state"), || {
            let v = *el.get_value().get()?;
            let s = v.pow(&power);

            Ok(s)
        })?;

        let dummy_quintic_box = QuinticSBox::<E> {
            _marker: std::marker::PhantomData,
        };
        let fifth = dummy_quintic_box
            .apply_constraints(cs.namespace(|| "apply quintic sbox for powering sbox"), &f)?;

        cs.enforce(
            || "enforce inverse box for LC",
            |_| el.lc(E::Fr::one()) - fifth.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );

        let f = Num::<E>::from(f);

        Ok(f)
    }
}

pub fn rescue_hash<E: RescueEngine, CS>(
    mut cs: CS,
    input: &[AllocatedNum<E>],
    params: &E::Params,
) -> Result<Vec<AllocatedNum<E>>, SynthesisError>
where
    <<E as RescueEngine>::Params as RescueHashParams<E>>::SBox0: CsSBox<E>,
    <<E as RescueEngine>::Params as RescueHashParams<E>>::SBox1: CsSBox<E>,
    CS: ConstraintSystem<E>,
{
    assert!(input.len() > 0);
    assert!(input.len() < 256);
    let input_len_as_fe = {
        let mut repr = <E::Fr as PrimeField>::Repr::default();
        repr.as_mut()[0] = input.len() as u64;
        let len_fe = <E::Fr as PrimeField>::from_repr(repr).unwrap();

        len_fe
    };

    let output_len = params.output_len() as usize;
    let absorbtion_len = params.rate() as usize;
    let t = params.state_width();
    let rate = params.rate();

    let mut absorbtion_cycles = input.len() / absorbtion_len;
    if input.len() % absorbtion_len != 0 {
        absorbtion_cycles += 1;
    }

    // convert input into Nums
    let mut input = input.to_vec();
    input.resize(
        absorbtion_cycles * absorbtion_len,
        AllocatedNum::one::<CS>(),
    );

    let mut it = input.into_iter();

    // unroll first round manually
    let mut state = {
        let mut state = Vec::with_capacity(t as usize);
        for _ in 0..rate {
            let as_num = Num::<E>::from(it.next().unwrap());
            state.push(as_num);
        }
        for _ in rate..(t - 1) {
            state.push(Num::<E>::zero());
        }

        // specialize into last state element
        {
            let mut lc = Num::<E>::zero();
            lc = lc.add_constant(CS::one(), input_len_as_fe);

            state.push(lc);
        }

        assert_eq!(state.len(), t as usize);

        rescue_mimc_over_lcs(
            cs.namespace(|| "rescue mimc for absorbtion round 0"),
            &state,
            params,
        )?
    };

    for i in 1..absorbtion_cycles {
        for word in 0..rate {
            state[word as usize].add_assign_number_with_coeff(&it.next().unwrap(), E::Fr::one());
        }

        state = rescue_mimc_over_lcs(
            cs.namespace(|| format!("rescue mimc for absorbtion round {}", i)),
            &state,
            params,
        )?;
    }

    debug_assert!(it.next().is_none());

    let mut result = vec![];

    for (i, num) in state[..output_len].iter().enumerate() {
        let allocated = num
            .clone()
            .into_allocated_num(cs.namespace(|| format!("collapse output word {}", i)))?;

        result.push(allocated);
    }

    Ok(result)
}

pub fn rescue_mimc_over_lcs<E: RescueEngine, CS>(
    mut cs: CS,
    input: &[Num<E>],
    params: &E::Params,
) -> Result<Vec<Num<E>>, SynthesisError>
where
    <<E as RescueEngine>::Params as RescueHashParams<E>>::SBox0: CsSBox<E>,
    <<E as RescueEngine>::Params as RescueHashParams<E>>::SBox1: CsSBox<E>,
    CS: ConstraintSystem<E>,
{
    let state_len = params.state_width() as usize;

    assert_eq!(input.len(), state_len);

    let mut state: Vec<Num<E>> = Vec::with_capacity(input.len());
    for (_i, (c, &constant)) in input
        .iter()
        .cloned()
        .zip(params.round_constants(0).iter())
        .enumerate()
    {
        let with_constant = c.add_constant(CS::one(), constant);

        state.push(with_constant);
    }

    let mut state = Some(state);

    // parameters use number of rounds that is number of invocations of each SBox,
    // so we double
    for round_num in 0..(2 * params.num_rounds()) {
        // apply corresponding sbox
        let tmp = if round_num & 1u32 == 0 {
            params.sbox_0().apply_constraints_on_lc_for_set(
                cs.namespace(|| format!("apply SBox_0 for round {}", round_num)),
                state.take().unwrap(),
            )?
        } else {
            params.sbox_1().apply_constraints_on_lc_for_set(
                cs.namespace(|| format!("apply SBox_1 for round {}", round_num)),
                state.take().unwrap(),
            )?
        };

        // apply multiplication by MDS

        let mut linear_transformation_results_scratch = Vec::with_capacity(state_len);

        let round_constants = params.round_constants(round_num + 1);
        for row_idx in 0..state_len {
            let row = params.mds_matrix_row(row_idx as u32);
            let linear_applied = scalar_product_over_lc_of_length_one(&tmp[..], row);
            let with_round_constant =
                linear_applied.add_constant(CS::one(), round_constants[row_idx]);
            linear_transformation_results_scratch.push(with_round_constant);
        }

        state = Some(linear_transformation_results_scratch);
    }

    Ok(state.unwrap())
}

fn scalar_product<E: Engine>(input: &[AllocatedNum<E>], by: &[E::Fr]) -> Num<E> {
    assert!(input.len() == by.len());
    let mut result = Num::zero();
    for (a, b) in input.iter().zip(by.iter()) {
        result = result.add_number_with_coeff(a, *b);
    }

    result
}

fn scalar_product_over_lc_of_length_one<E: Engine>(input: &[Num<E>], by: &[E::Fr]) -> Num<E> {
    assert!(input.len() == by.len());
    let mut result = Num::zero();
    for (a, b) in input.iter().zip(by.iter()) {
        if a.is_empty() {
            continue;
        }
        let var = a.unwrap_as_allocated_num();
        result.add_assign_number_with_coeff(&var, *b);
    }

    result
}

enum RescueOpMode<E: RescueEngine> {
    AccumulatingToAbsorb(Vec<AllocatedNum<E>>),
    SqueezedInto(Vec<Num<E>>),
}

pub struct StatefulRescueGadget<E: RescueEngine> {
    internal_state: Vec<Num<E>>,
    mode: RescueOpMode<E>,
}

impl<E: RescueEngine> StatefulRescueGadget<E> {
    pub fn new(params: &E::Params) -> Self {
        let op = RescueOpMode::AccumulatingToAbsorb(Vec::with_capacity(params.rate() as usize));

        Self {
            internal_state: vec![Num::<E>::zero(); params.state_width() as usize],
            mode: op,
        }
    }

    pub fn specialize<CS: ConstraintSystem<E>>(&mut self, _cs: CS, dst: u8) {
        assert!(dst > 0);
        let dst_as_fe = {
            let mut repr = <E::Fr as PrimeField>::Repr::default();
            repr.as_mut()[0] = dst as u64;
            let dst_as_fe = <E::Fr as PrimeField>::from_repr(repr).unwrap();

            dst_as_fe
        };

        match self.mode {
            RescueOpMode::AccumulatingToAbsorb(ref into) => {
                assert_eq!(
                    into.len(),
                    0,
                    "can not specialize sponge that absorbed something"
                )
            }
            _ => {
                panic!("can not specialized sponge in squeezing state");
            }
        }

        let last_state_idx = self.internal_state.len() - 1;
        assert!(self.internal_state[last_state_idx].is_empty());

        let mut lc = Num::<E>::zero();
        lc = lc.add_constant(CS::one(), dst_as_fe);

        self.internal_state[last_state_idx] = lc;
    }

    fn absorb_single_value<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        value: &AllocatedNum<E>,
        params: &E::Params,
    ) -> Result<(), SynthesisError> {
        match self.mode {
            RescueOpMode::AccumulatingToAbsorb(ref mut into) => {
                // two cases
                // either we have accumulated enough already and should to
                // a mimc round before accumulating more, or just accumulate more
                let rate = params.rate() as usize;
                if into.len() < rate {
                    into.push(value.clone());
                } else {
                    for i in 0..rate {
                        self.internal_state[i].add_assign_number_with_coeff(&into[i], E::Fr::one());
                    }

                    self.internal_state = rescue_mimc_over_lcs(
                        cs.namespace(|| "perform mimc round"),
                        &self.internal_state,
                        &params,
                    )?;

                    into.truncate(0);
                    into.push(value.clone());
                }
            }
            RescueOpMode::SqueezedInto(_) => {
                // we don't need anything from the output, so it's dropped

                let mut s = Vec::with_capacity(params.rate() as usize);
                s.push(value.clone());

                let op = RescueOpMode::AccumulatingToAbsorb(s);
                self.mode = op;
            }
        }

        Ok(())
    }

    pub fn absorb<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        input: &[AllocatedNum<E>],
        params: &E::Params,
    ) -> Result<(), SynthesisError> {
        assert!(input.len() > 0);
        assert!(input.len() < 256);
        let absorbtion_len = params.rate() as usize;

        let mut absorbtion_cycles = input.len() / absorbtion_len;
        if input.len() % absorbtion_len != 0 {
            absorbtion_cycles += 1;
        }

        let mut input = input.to_vec();
        input.resize(
            absorbtion_cycles * absorbtion_len,
            AllocatedNum::one::<CS>(),
        );

        let it = input.into_iter();

        for (idx, val) in it.enumerate() {
            self.absorb_single_value(
                cs.namespace(|| format!("absorb index {}", idx)),
                &val,
                &params,
            )?;
        }

        Ok(())
    }

    pub fn squeeze_out_single<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        params: &E::Params,
    ) -> Result<AllocatedNum<E>, SynthesisError> {
        match self.mode {
            RescueOpMode::AccumulatingToAbsorb(ref mut into) => {
                let rate = params.rate() as usize;
                assert_eq!(into.len(), rate, "padding was necessary!");
                // two cases
                // either we have accumulated enough already and should to
                // a mimc round before accumulating more, or just accumulate more
                for i in 0..rate {
                    self.internal_state[i].add_assign_number_with_coeff(&into[i], E::Fr::one());
                }
                self.internal_state = rescue_mimc_over_lcs(
                    cs.namespace(|| "perform mimc round"),
                    &self.internal_state,
                    &params,
                )?;

                // we don't take full internal state, but only the rate
                let mut sponge_output = self.internal_state[0..rate].to_vec();
                let output = sponge_output
                    .drain(0..1)
                    .next()
                    .unwrap()
                    .into_allocated_num(
                        cs.namespace(|| "transform sponge output into allocated number"),
                    )?;

                let op = RescueOpMode::SqueezedInto(sponge_output);
                self.mode = op;

                return Ok(output);
            }
            RescueOpMode::SqueezedInto(ref mut into) => {
                assert!(into.len() > 0, "squeezed state is depleted!");
                let output = into.drain(0..1).next().unwrap().into_allocated_num(
                    cs.namespace(|| "transform sponge output into allocated number"),
                )?;

                return Ok(output);
            }
        }
    }
}

fn print_lc<E: Engine>(input: &[Num<E>]) {
    for el in input.iter() {
        println!("{}", el.get_value().unwrap());
    }
}

fn print_nums<E: Engine>(input: &[AllocatedNum<E>]) {
    for el in input.iter() {
        println!("{}", el.get_value().unwrap());
    }
}
