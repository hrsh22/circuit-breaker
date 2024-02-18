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

template revealNFT() {
    signal input attribute1;
    signal input attribute2;
    signal input attribute3;
    signal input hashKey;

    signal output out;

    // hash attribute
    component cHash = hashCharacter();
    cHash.attribute[0] <== attribute1;
    cHash.attribute[1] <== attribute2;
    cHash.attribute[2] <== attribute3;
    cHash.hashKey <== hashKey;

    out <== cHash.out;
}

component main = revealNFT();