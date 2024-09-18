use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use arkeddsa::SigningKey;
use num_bigint::BigUint;

use std::{collections::HashMap, env::current_dir, time::Instant};

use nova_scotia::{
    circom::reader::load_r1cs, create_public_params, create_recursive_circuit, FileLocation, F, S,
};
use nova_snark::{provider, CompressedSNARK, PublicParams};

use digest::Digest;
use rand_core::OsRng;
use serde_json::json;

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

pub struct EddsaCircom {
    // Checks equation equality.
    enabled: usize,
    // Pubkey x coordinate.
    ax: BigUint,
    // Pubkey y coordinate.
    ay: BigUint,
    // Signature's S.
    s: BigUint,
    // Signature's R's x coordinate.
    r8x: BigUint,
    // Signature's R's y coordinate.
    r8y: BigUint,
    // Message
    m: String,
}

impl EddsaCircom {
    pub fn new<TE: TECurveConfig + Clone, D: Digest>() -> Self
    where
        TE::BaseField: Absorb + PrimeField,
    {
        let poseidon = poseidon_config();
        let signing_key = SigningKey::<TE>::generate::<D>(&mut OsRng).unwrap();
        let message = "0";
        let signature = signing_key.sign::<D, _>(&poseidon, message.as_bytes());

        let enabled = 1;
        let public_key = signing_key.public_key();
        let (ax, ay) = public_key.xy();
        let ax = BigUint::from_bytes_be(ax.to_string().as_bytes());
        let ay = BigUint::from_bytes_be(ay.to_string().as_bytes());
        let s = BigUint::from_bytes_be(signature.s().to_string().as_bytes());
        let (r8x, r8y) = signature.r().xy().unwrap();
        let r8x = BigUint::from_bytes_be(r8x.to_string().as_bytes());
        let r8y = BigUint::from_bytes_be(r8y.to_string().as_bytes());

        Self {
            enabled,
            ax,
            ay,
            s,
            r8x,
            r8y,
            m: message.to_owned(),
        }
    }
}

pub fn eddsa_circom(circuit_filepath: String, witness_gen_filepath: String) {
    type G1 = provider::bn256_grumpkin::bn256::Point;
    type G2 = provider::bn256_grumpkin::grumpkin::Point;

    let eddsa = EddsaCircom::new::<ark_ed_on_bn254::EdwardsConfig, sha2::Sha512>();

    println!(
        "Running test with witness generator: {} and group: {}",
        witness_gen_filepath,
        std::any::type_name::<G1>()
    );

    let root = current_dir().unwrap();
    let circuit_file = root.join(circuit_filepath);
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file));
    let witness_generator_file = root.join(witness_gen_filepath);

    let iteration_count = 1;
    let priv_input_2 = eddsa.ax;
    let priv_input_3 = eddsa.ay;
    let priv_input_4 = eddsa.s;
    let priv_input_5 = eddsa.r8x;
    let priv_input_6 = eddsa.r8y;
    let priv_input_7 = eddsa.m;

    let mut private_inputs = Vec::new();

    for _ in 0..iteration_count {
        let mut private_input = HashMap::new();
        private_input.insert("priv_hash_2".to_string(), json!(priv_input_2));
        private_input.insert("priv_hash_3".to_string(), json!(priv_input_3));
        private_input.insert("priv_hash_4".to_string(), json!(priv_input_4));
        private_input.insert("priv_hash_5".to_string(), json!(priv_input_5));
        private_input.insert("priv_hash_6".to_string(), json!(priv_input_6));
        private_input.insert("priv_hash_7".to_string(), json!(priv_input_7));
        private_inputs.push(private_input);
    }

    let start_public_input = [F::<G1>::from(eddsa.enabled as u64)];

    let pp: PublicParams<G1, G2, _, _> = create_public_params(r1cs.clone());

    println!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );

    println!(
        "Number of constraints per step (secondary circuit): {}",
        pp.num_constraints().1
    );

    println!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );

    println!(
        "Number of variables per step (secondary circuit): {}",
        pp.num_variables().1
    );

    println!("Creating a RecursiveSNARK...");
    let start = Instant::now();
    let recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_file.clone()),
        r1cs.clone(),
        private_inputs,
        start_public_input.to_vec(),
        &pp,
    )
    .unwrap();
    println!("RecursiveSNARK creation took {:?}", start.elapsed());

    let z0_secondary = [F::<G2>::from(0)];

    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let res = recursive_snark.verify(&pp, iteration_count, &start_public_input, &z0_secondary);
    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res,
        start.elapsed()
    );
    assert!(res.is_ok());

    println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    let start = Instant::now();
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::setup(&pp).unwrap();
    let res = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::prove(&pp, &pk, &recursive_snark);
    println!(
        "CompressedSNARK::prove: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();

    println!("Verifying a CompressedSNARK...");
    let start = Instant::now();
    let res = compressed_snark.verify(
        &vk,
        iteration_count,
        start_public_input.to_vec(),
        z0_secondary.to_vec(),
    );
    println!(
        "CompressedSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());

    /*
    You can check results from https://zkrepl.dev/
    Ensure that you get the following output in your terminal
    RecursiveSNARK::verify: Ok(([
        0x036435f0a0702c00f80a5102a599a6081ca80cf615381a3f7cb20cff4e82b121],
       [0x0000000000000000000000000000000000000000000000000000000000000000]
    ))
    */
}
