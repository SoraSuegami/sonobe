import * as wasm from "../pkg/sonobe_wasm_prover";
const ff = require('ffjavascript');
// const stringifyBigInts = ff.utils.stringifyBigInts;
// const circom_tester = require("circom_tester");
// const wasm_tester = circom_tester.wasm;
// import * as path from "path";
// const p = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
// const field = new ff.F1Field(p);
// const relayerUtils = require("../../utils");
import { readFileSync } from "fs";

function readFileAsUint8Array(filePath: string): Uint8Array {
    const buffer = readFileSync(filePath);
    return new Uint8Array(buffer);
}

jest.setTimeout(1440000);
describe("Email Auth", () => {
    let r1cs_raw: Uint8Array;
    let wasm_bytes: Uint8Array;
    let cs_params: Uint8Array;
    let cf_cs_params: Uint8Array;
    let g16_pk: Uint8Array;
    beforeAll(async () => {
        // read Uint8Array from file
        r1cs_raw = readFileAsUint8Array("./tests/test_data/with_external_inputs/with_external_inputs.r1cs");
        wasm_bytes = readFileAsUint8Array("./tests/test_data/with_external_inputs/with_external_inputs.wasm");
        cs_params = readFileAsUint8Array("./tests/test_data/with_external_inputs/cs_params.bin");
        cf_cs_params = readFileAsUint8Array("./tests/test_data/with_external_inputs/cf_cs_params.bin");
        g16_pk = readFileAsUint8Array("./tests/test_data/with_external_inputs/g16_pk.bin");
        wasm.init_panic_hook();
    });

    it("should prove", async () => {
        const init_state = ["3"];
        /*
        vec![Fr::from(6u32), Fr::from(7u32)],
        vec![Fr::from(8u32), Fr::from(9u32)],
        vec![Fr::from(10u32), Fr::from(11u32)],
        vec![Fr::from(12u32), Fr::from(13u32)],
        vec![Fr::from(14u32), Fr::from(15u32)],
        vec![Fr::from(6u32), Fr::from(7u32)],
        vec![Fr::from(8u32), Fr::from(9u32)],
        vec![Fr::from(10u32), Fr::from(11u32)],
        vec![Fr::from(12u32), Fr::from(13u32)],
        vec![Fr::from(14u32), Fr::from(15u32)],
         */
        const external_inputs = [
            "6",
            "7",
            "8",
            "9",
            "10",
            "11",
            "12",
            "13",
            "14",
            "15",
            "6",
            "7",
            "8",
            "9",
            "10",
            "11",
            "12",
            "13",
            "14",
            "15",
        ];
        const n_steps = 100;
        const res = wasm.full_prove(r1cs_raw, wasm_bytes, cs_params, cf_cs_params, g16_pk, init_state, external_inputs, n_steps);
        console.log(res);
    });
});

