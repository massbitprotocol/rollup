use halo2_gadgets::ecc::{
    chip::{find_zs_and_us, BaseFieldElem, FixedPoint, H, NUM_WINDOWS, NUM_WINDOWS_SHORT},
    FixedPoints,
};
use halo2_proofs::halo2curves::{
    group::{ff::PrimeField, Curve, Group},
    pasta::pallas,
};

//use halo2_proofs::pasta::group::ff::PrimeField;
use halo2_gadgets::sinsemilla::primitives::CommitDomain;
use halo2_gadgets::sinsemilla::CommitDomains;

use lazy_static::lazy_static;

use crate::Fp;

pub const PERSONALIZATION: &str = "MerkleCRH";
lazy_static! {
    static ref BASE: pallas::Affine = pallas::Point::generator().to_affine();
    static ref ZS_AND_US: Vec<(u64, [Fp; H])> = find_zs_and_us(*BASE, NUM_WINDOWS).unwrap();
    static ref ZS_AND_US_SHORT: Vec<(u64, [Fp; H])> =
        find_zs_and_us(*BASE, NUM_WINDOWS_SHORT).unwrap();
    static ref COMMIT_DOMAIN: CommitDomain = CommitDomain::new(PERSONALIZATION);
    //static ref Q: pallas::Affine = COMMIT_DOMAIN.Q().to_affine();
    //static ref R: pallas::Affine = COMMIT_DOMAIN.R().to_affine();
    //static ref R_ZS_AND_US: Vec<(u64, [Fp; H])> = find_zs_and_us(*R, NUM_WINDOWS).unwrap();
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct TestFixedBases;
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct FullWidth(pallas::Affine, &'static [(u64, [Fp; H])]);
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct BaseField;
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Short;

impl FixedPoint<pallas::Affine> for BaseField {
    type FixedScalarKind = BaseFieldElem;

    fn generator(&self) -> pallas::Affine {
        *BASE
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        ZS_AND_US
            .iter()
            .map(|(_, us)| {
                [
                    us[0].to_repr(),
                    us[1].to_repr(),
                    us[2].to_repr(),
                    us[3].to_repr(),
                    us[4].to_repr(),
                    us[5].to_repr(),
                    us[6].to_repr(),
                    us[7].to_repr(),
                ]
            })
            .collect()
    }

    fn z(&self) -> Vec<u64> {
        ZS_AND_US.iter().map(|(z, _)| *z).collect()
    }
}

impl FixedPoints<pallas::Affine> for TestFixedBases {
    type FullScalar = FullWidth;
    type ShortScalar = Short;
    type Base = BaseField;
}
/*
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TestHashDomain;
impl HashDomains<pallas::Affine> for TestHashDomain {
    fn Q(&self) -> pallas::Affine {
        *Q
    }
}

// This test does not make use of the CommitDomain.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TestCommitDomain;
impl CommitDomains<pallas::Affine, TestFixedBases, TestHashDomain> for TestCommitDomain {
    fn r(&self) -> FullWidth {
        FullWidth::from_parts(*R, &R_ZS_AND_US)
    }

    fn hash_domain(&self) -> TestHashDomain {
        TestHashDomain
    }
}

 */
