use crate::hasher::rescue_hasher::RescueEngine;
use ff::Field;
use halo2_proofs::halo2curves::pairing::Engine;
use num::integer::ExtendedGcd;
use num::BigInt;
use rand::Rng;
use std::io::{self, Read};
use std::ops::{MulAssign, SubAssign};

// For simplicity we'll not generate a matrix using a way from the paper and sampling
// an element with some zero MSBs and instead just sample and retry
pub fn generate_mds_matrix<E: RescueEngine, R: Rng>(t: u32, rng: &mut R) -> Vec<E::Fr> {
    loop {
        let x: Vec<E::Fr> = (0..t).map(|_| rng.gen()).collect();
        let y: Vec<E::Fr> = (0..t).map(|_| rng.gen()).collect();

        let mut invalid = false;

        // quick and dirty check for uniqueness of x
        for i in 0..(t as usize) {
            if invalid {
                continue;
            }
            let el = x[i];
            for other in x[(i + 1)..].iter() {
                if el == *other {
                    invalid = true;
                    break;
                }
            }
        }

        if invalid {
            continue;
        }

        // quick and dirty check for uniqueness of y
        for i in 0..(t as usize) {
            if invalid {
                continue;
            }
            let el = y[i];
            for other in y[(i + 1)..].iter() {
                if el == *other {
                    invalid = true;
                    break;
                }
            }
        }

        if invalid {
            continue;
        }

        // quick and dirty check for uniqueness of x vs y
        for i in 0..(t as usize) {
            if invalid {
                continue;
            }
            let el = x[i];
            for other in y.iter() {
                if el == *other {
                    invalid = true;
                    break;
                }
            }
        }

        if invalid {
            continue;
        }

        // by previous checks we can be sure in uniqueness and perform subtractions easily
        let mut mds_matrix = vec![E::Fr::zero(); (t * t) as usize];
        for (i, x) in x.into_iter().enumerate() {
            for (j, y) in y.iter().enumerate() {
                let place_into = i * (t as usize) + j;
                let mut element = x;
                element.sub_assign(y);
                mds_matrix[place_into] = element;
            }
        }

        // now we need to do the inverse
        batch_inversion::<E>(&mut mds_matrix[..]);

        return mds_matrix;
    }
}

pub fn batch_inversion<E: RescueEngine>(v: &mut [E::Fr]) {
    // Montgomery’s Trick and Fast Implementation of Masked AES
    // Genelle, Prouff and Quisquater
    // Section 3.2

    // First pass: compute [a, ab, abc, ...]
    let mut prod = Vec::with_capacity(v.len());
    let mut tmp = E::Fr::one();
    for g in v
        .iter()
        // Ignore zero elements
        .filter(|g| !g.is_zero())
    {
        tmp.mul_assign(&g);
        prod.push(tmp);
    }

    // Invert `tmp`.
    tmp = tmp.inverse().unwrap(); // Guaranteed to be nonzero.

    // Second pass: iterate backwards to compute inverses
    for (g, s) in v
        .iter_mut()
        // Backwards
        .rev()
        // Ignore normalized elements
        .filter(|g| !g.is_zero())
        // Backwards, skip last element, fill in one for last term.
        .zip(prod.into_iter().rev().skip(1).chain(Some(E::Fr::one())))
    {
        // tmp := tmp * g.z; g.z := tmp * s = 1/z
        let mut newtmp = tmp;
        newtmp.mul_assign(&g);
        *g = tmp;
        g.mul_assign(&s);
        tmp = newtmp;
    }
}

/// Reads a little endian integer into this representation.
pub fn read_le<R: Read, Rep: AsMut<[u8]>>(input: &mut Rep, mut reader: R) -> io::Result<()> {
    use byteorder::{LittleEndian, ReadBytesExt};

    for digit in input.as_mut().iter_mut() {
        *digit = reader.read_u64::<LittleEndian>()?;
    }

    Ok(())
}
