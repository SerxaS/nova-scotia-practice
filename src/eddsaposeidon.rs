#[cfg(test)]
mod test {
    use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
    use ark_crypto_primitives::sponge::Absorb;
    use ark_ec::twisted_edwards::TECurveConfig;
    use ark_ff::PrimeField;
    use arkeddsa::SigningKey;
    use digest::Digest;
    use rand_core::OsRng;

    /// Generates Poseidon constants and returns the config.
    pub fn poseidon_config<F: PrimeField>(
        rate: usize,
        full_rounds: usize,
        partial_rounds: usize,
    ) -> PoseidonConfig<F> {
        let prime_bits = F::MODULUS_BIT_SIZE as u64;
        let (ark, mds) = find_poseidon_ark_and_mds(
            prime_bits,
            rate,
            full_rounds as u64,
            partial_rounds as u64,
            0,
        );

        PoseidonConfig::new(full_rounds, partial_rounds, 5, mds, ark, rate, 1)
    }

    fn run_test<TE: TECurveConfig + Clone, D: Digest>()
    where
        TE::BaseField: Absorb + PrimeField,
    {
        let poseidon = poseidon_config(4, 8, 55);
        let signing_key = SigningKey::<TE>::generate::<D>(&mut OsRng).unwrap();
        let message = b"abc 123 '' @";
        let signature = signing_key.sign::<D, _>(&poseidon, message);
        let public_key = signing_key.public_key();

        public_key.verify(&poseidon, message, &signature).unwrap();
    }

    #[test]
    fn eddsa_test() {
        run_test::<ark_ed_on_bn254::EdwardsConfig, sha2::Sha512>();
    }
}
