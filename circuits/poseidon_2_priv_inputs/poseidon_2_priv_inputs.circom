pragma circom 2.1.9;

include "../node_modules/circomlib/circuits/poseidon.circom";


template Example() {
    signal input step_in;

    signal output step_out;

    signal input priv_hash_1;
    signal input priv_hash_2;

    component hash_1 = Poseidon(2);
    hash_1.inputs[0] <== step_in;
    hash_1.inputs[1] <== priv_hash_1;       

    component hash_2 = Poseidon(2);
    hash_2.inputs[0] <== hash_1.out;    
    hash_2.inputs[1] <== priv_hash_2;    

    step_out <== hash_2.out;
}

component main { public [ step_in ] } = Example();