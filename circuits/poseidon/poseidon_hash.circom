pragma circom 2.1.9;

include "../node_modules/circomlib/circuits/poseidon.circom";


template Example() {
    signal input step_in[2];

    signal output step_out[2];

    signal input priv_hash_input;

    component hash_1 = Poseidon(2);
    hash_1.inputs[0] <== step_in[0];
    hash_1.inputs[1] <== step_in[1];

    step_out[0] <== hash_1.out;    

    component hash_2 = Poseidon(1);
    hash_2.inputs[0] <== priv_hash_input;    

    component hash_3 = Poseidon(2);
    hash_3.inputs[0] <== hash_1.out;
    hash_3.inputs[1] <== hash_2.out;

    step_out[1] <== hash_3.out;
}

component main { public [ step_in ] } = Example();