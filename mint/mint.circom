include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/gates.circom";
include "../node_modules/circomlib/circuits/mimcsponge.circom";

template hashCharacter() {
    signal input attribute[3];
    signal input hashKey;
    signal output out;

    component mimc = MiMCSponge(4, 220, 1);
    mimc.ins[0] <== attribute[0];
    mimc.ins[1] <== attribute[1];
    mimc.ins[2] <== attribute[2];
    mimc.ins[3] <== hashKey;

    mimc.k <== 0;

    out <== mimc.outs[0];
}

template mint(MAX_VAL) {
    signal input attribute1;
    signal input attribute2;
    signal input attribute3;
    signal input hashKey;

    signal output out; // hashed value of attributes

    // check whether attributes were less than or equan to X
    component l1 = LessEqThan(32);
    l1.in[0] <== attribute1 + attribute2 + attribute3;
    l1.in[1] <== MAX_VAL;

    l1.out === 1;

    // hash attribute
    component cHash = hashCharacter();
    cHash.attribute[0] <== attribute1;
    cHash.attribute[1] <== attribute2;
    cHash.attribute[2] <== attribute3;
    cHash.hashKey <== hashKey;

    out <== cHash.out;
}

component main = mint(10);