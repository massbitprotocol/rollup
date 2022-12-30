use halo2_proofs::
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct RollupHashDomain;
impl HashDomains<pallas::Affine> for RollupHashDomain {
    fn Q(&self) -> pallas::Affine {
        *Q
    }
}