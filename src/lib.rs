mod bn254_2_inputs;
mod bn254_3_inputs;
mod pasta_2_inputs;
mod poseidon;
mod poseidon_2_priv_inputs;

#[cfg(test)]
mod test {
    use crate::bn254_2_inputs::run_bn254_2inputs;
    use crate::bn254_3_inputs::run_bn254_3inputs;
    use crate::pasta_2_inputs::run_pasta_2inputs;
    use crate::poseidon::poseidon;
    use crate::poseidon_2_priv_inputs::poseidon_2_priv_inputs;

    #[test]
    fn test_bn254_2inputs_folding() {
        let circuit_filepath = "circuits/2inputs/bn254/bn254.r1cs";
        let witness_gen_filepath = "circuits/2inputs/bn254/bn254.wasm";

        run_bn254_2inputs(
            circuit_filepath.to_string().clone(),
            witness_gen_filepath.to_string(),
        );
    }

    #[test]
    fn test_pasta_2inputs_folding() {
        let circuit_filepath = "circuits/2inputs/pasta/pasta.r1cs";
        let witness_gen_filepath = "circuits/2inputs/pasta/pasta.wasm";

        run_pasta_2inputs(
            circuit_filepath.to_string().clone(),
            witness_gen_filepath.to_string(),
        );
    }

    #[test]
    fn test_bn254_3inputs_folding() {
        let circuit_filepath = "circuits/3inputs/bn254/3inputs.r1cs";
        let witness_gen_filepath = "circuits/3inputs/bn254/3inputs.wasm";

        run_bn254_3inputs(
            circuit_filepath.to_string().clone(),
            witness_gen_filepath.to_string(),
        );
    }

    #[test]
    fn poseidon_test() {
        let circuit_filepath = "circuits/poseidon/poseidon_hash.r1cs";
        let witness_gen_filepath = "circuits/poseidon/poseidon_hash.wasm";

        poseidon(
            circuit_filepath.to_string().clone(),
            witness_gen_filepath.to_string(),
        );
    }

    #[test]
    fn poseidon_2_priv_inputs_test() {
        let circuit_filepath = "circuits/poseidon_2_priv_inputs/poseidon_2_priv_inputs.r1cs";
        let witness_gen_filepath = "circuits/poseidon_2_priv_inputs/poseidon_2_priv_inputs.wasm";

        poseidon_2_priv_inputs(
            circuit_filepath.to_string().clone(),
            witness_gen_filepath.to_string(),
        );
    }   
}
