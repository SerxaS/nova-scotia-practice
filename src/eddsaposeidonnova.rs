use ark_ff::PrimeField;

#[allow(non_snake_case)]
pub struct EddsaCircom<F: PrimeField> {
    enabled: usize,
    Ax: F,
    Ay: F,
    S: F,
    R8x: F,
    R8y: F,
    M: F,
}

impl<F: PrimeField> EddsaCircom<F> {
    pub fn new() {}
}
