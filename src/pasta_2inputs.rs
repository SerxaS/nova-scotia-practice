use std::{collections::HashMap, env::current_dir, time::Instant};

// Consider nova scotia as some middleware, that will make it easy for you to interact with nova.
use nova_scotia::{
    circom::reader::load_r1cs, create_public_params, create_recursive_circuit, FileLocation, F, S,
};
use nova_snark::{CompressedSNARK, PublicParams};
use serde_json::json;

pub fn run_pasta_2inputs(circuit_filepath: String, witness_gen_filepath: String) {
    /*
    1. Define the curve cycle that we want to use. We will use the vesta/pallas curve cycle.
    */
    type G1 = pasta_curves::vesta::Point;
    type G2 = pasta_curves::pallas::Point;

    println!(
        "Running test with witness generator: {} and group: {}",
        witness_gen_filepath,
        std::any::type_name::<G1>()
    );

    /*
    2. Load the r1cs and witness generator files.
    */
    let root = current_dir().unwrap();
    let circuit_file = root.join(circuit_filepath);
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file));
    let witness_generator_file = root.join(witness_gen_filepath);

    /*
    3. Setuping the private auxiliary inputs that we will use when folding. They are two public
       inputs at each folding steps (step_in[0], step_in[1]) and adder is the private input
       (auxiliary input) that we have.

            step_out[0] <== step_in[0] + adder;
            step_out[1] <== step_in[0] + step_in[1];

                step_in[0]   step_in[1]   adder
                    10           10         3   <-- inputs
                    13           20         3
                    16           33         3
                    19           49         3
                    22           68         3
                    25           90         -   <-- state of things when we output results
    */
    let iteration_count = 5;
    let adder = 3;
    let mut private_inputs = Vec::new();

    for _ in 0..iteration_count {
        let mut private_input = HashMap::new();
        private_input.insert("adder".to_string(), json!(adder));
        private_inputs.push(private_input);
    }

    /*
    4. Set the starting public inputs that we are going to use. (step_in[0], step_in[1])
    */
    let start_public_input = [F::<G1>::from(10), F::<G1>::from(10)];

    /*
    5. Create the public parameters for the recursive snark.
    */
    let pp: PublicParams<G1, G2, _, _> = create_public_params(r1cs.clone());

    /*
    6. We can print some info about the recursive snark that we are building
    */
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

    /*
    7. Create the recursive snark.
    */
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

    /*
    8. Verify it
    */
    let z0_secondary = [F::<G2>::from(0)];

    // Verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let res = recursive_snark.verify(&pp, iteration_count, &start_public_input, &z0_secondary);
    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res,
        start.elapsed()
    );
    assert!(res.is_ok());

    let z_last = res.unwrap().0;

    assert_eq!(z_last[0], F::<G1>::from(25));
    assert_eq!(z_last[1], F::<G1>::from(90));

    /*
    9. The proof is quite large... so we will compress it using SPARTAN.
    */
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

    /*
    10. Verify the compressed snark
    */
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
    Ensure that you get the following output in your terminal
    RecursiveSNARK::verify: Ok(([
        0x0000000000000000000000000000000000000000000000000000000000000019,
        0x000000000000000000000000000000000000000000000000000000000000005a],
        [0x0000000000000000000000000000000000000000000000000000000000000000]
    ))
    */
}
