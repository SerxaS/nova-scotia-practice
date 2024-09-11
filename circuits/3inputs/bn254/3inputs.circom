pragma circom 2.1.9;

template Example() {
    signal input step_in[3];

    signal output step_out[3];

    signal input adder;

    step_out[0] <== step_in[0] + step_in[1] + adder;
    step_out[1] <== step_in[0] + step_in[1] + step_in[2] + adder;
    step_out[2] <== step_in[0] + step_in[1] + step_in[2];
}

component main { public [ step_in ] } = Example();