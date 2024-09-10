mod bn254;
mod pasta;

#[cfg(test)]
mod test {
    use crate::bn254::run_bn254;
    use crate::pasta::run_pasta;

    #[test]
    fn test_bn254_folding() {
        let circuit_filepath = "circuits/bn254/bn254.r1cs";
        let witness_gen_filepath = "circuits/bn254/bn254.wasm";

        run_bn254(
            circuit_filepath.to_string().clone(),
            witness_gen_filepath.to_string(),
        );
    }

    #[test]
    fn test_pasta_folding() {
        let circuit_filepath = "circuits/pasta/pasta.r1cs";
        let witness_gen_filepath = "circuits/pasta/pasta.wasm";

        run_pasta(
            circuit_filepath.to_string().clone(),
            witness_gen_filepath.to_string(),
        );
    }
}
