use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use arkeddsa::SigningKey;
use digest::Digest;
use rand_core::OsRng;

/// Generates Poseidon constants and returns the config.
pub fn poseidon_config<F: PrimeField>() -> PoseidonConfig<F> {
    let full_rounds = 8;
    let partial_rounds = 60;
    let alpha = 5;
    let rate = 4;

    let (ark, mds) = find_poseidon_ark_and_mds(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds,
        partial_rounds,
        0,
    );

    PoseidonConfig::new(
        full_rounds as usize,
        partial_rounds as usize,
        alpha,
        mds,
        ark,
        rate,
        1,
    )
}

pub struct EddsaCircom<F: PrimeField> {
    // Checks equation equality.
    enabled: usize,
    // Pubkey x coordinate.
    ax: F,
    // Pubkey y coordinate.
    ay: F,
    // Signature's S.
    s: F,
    // Signature's R's x coordinate.
    r8x: F,
    // Signature's R's y coordinate.
    r8y: F,
    // Message
    m: F,
}

impl<F: PrimeField> EddsaCircom<F> {
    fn new<TE: TECurveConfig + Clone, D: Digest>()
    where
        TE::BaseField: Absorb + PrimeField,
    {
        let poseidon = poseidon_config();
        let signing_key = SigningKey::<TE>::generate::<D>(&mut OsRng).unwrap();
        let message = b"abc 123 '' @";
        let signature = signing_key.sign::<D, _>(&poseidon, message);

        let public_key = signing_key.public_key();
        let (ax, ay) = public_key.xy();

        let s = signature.s();

        let (r8x, r8y) = signature.r().xy().unwrap();
    }
}
