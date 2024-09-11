mod bn254_2inputs;
mod bn254_3inputs;
mod pasta_2inputs;

#[cfg(test)]
mod test {
    use crate::bn254_2inputs::run_bn254_2inputs;
    use crate::bn254_3inputs::run_bn254_3inputs;
    use crate::pasta_2inputs::run_pasta_2inputs;

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
}
