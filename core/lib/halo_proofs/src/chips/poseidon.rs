use halo2_proofs::pasta::pallas;
/// Configuration for the Sinsemilla hash chip
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct PoseidonConfig<Hash, Commit, F>
    where
        Hash: HashDomains<pallas::Affine>,
        F: FixedPoints<pallas::Affine>,
        Commit: CommitDomains<pallas::Affine, F, Hash>,
{

}
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct PoseidonChip<Hash, Commit, F>
    where
        Hash: HashDomains<pallas::Affine>,
        Fixed: FixedPoints<pallas::Affine>,
        Commit: CommitDomains<pallas::Affine, F, Hash>,
{
    config: PoseidonConfig<Hash, Commit, F>,
}

pub trait PoseidonInstructions {

}
impl<Hash, Commit, F> PoseidonConfig<Hash, Commit, F>
    where
        Hash: HashDomains<pallas::Affine>,
        F: FixedPoints<pallas::Affine>,
        Commit: CommitDomains<pallas::Affine, F, Hash>,
{

}


impl<Hash, Commit, F> Chip<pallas::Base> for PoseidonChip<Hash, Commit, F>
    where
        Hash: HashDomains<pallas::Affine>,
        F: FixedPoints<pallas::Affine>,
        Commit: CommitDomains<pallas::Affine, F, Hash>,
{
    type Config = PoseidonConfig<Hash, Commit, F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
impl<Hash, Commit, F> PoseidonChip<Hash, Commit, F>
    where
        Hash: HashDomains<pallas::Affine>,
        F: FixedPoints<pallas::Affine>,
        Commit: CommitDomains<pallas::Affine, F, Hash>,
{
    /// Reconstructs this chip from the given config.
    pub fn construct(config: <Self as Chip<pallas::Base>>::Config) -> Self {
        Self { config }
    }

    /// Loads the lookup table required by this chip into the circuit.
    pub fn load(
        config: SinsemillaConfig<Hash, Commit, F>,
        layouter: &mut impl Layouter<pallas::Base>,
    ) -> Result<<Self as Chip<pallas::Base>>::Loaded, Error> {
        // Load the lookup table.
        config.generator_table.load(layouter)
    }

    /// # Side-effects
    ///
    /// All columns in `advices` and will be equality-enabled.
    #[allow(clippy::too_many_arguments)]
    #[allow(non_snake_case)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 5],
        witness_pieces: Column<Advice>,
        fixed_y_q: Column<Fixed>,
        lookup: (TableColumn, TableColumn, TableColumn),
        range_check: LookupRangeCheckConfig<pallas::Base, { sinsemilla::K }>,
    ) -> <Self as Chip<pallas::Base>>::Config {
        let config = PoseidonConfig::<Hash, Commit, F> {

        };
        config
    }
}

impl PoseidonInstructions<Hash, Commit, F> for PoseidonChip<Hash, Commit, F> {

}