import { expose, proxy } from 'comlink';

export type MultiThreads = typeof import('sonobe-wasm-prover');

let multiThreads: MultiThreads | null = null;
/**
 * Initialize the multi-threaded WASM module.
 * @returns The multi-threaded WASM module.
 */
export async function initMultiThreads(): Promise<MultiThreads> {
    if (multiThreads !== null) {
        console.log("multiThreads already initialized");
        return multiThreads;
    }
    multiThreads = await _initMultiThreads();
    return multiThreads;
}

async function _initMultiThreads(): Promise<MultiThreads> {
    const _multiThreads = await import(
        'sonobe-wasm-prover'
    );
    console.log(_multiThreads);
    await _multiThreads.default();
    console.log(`hardware: ${navigator.hardwareConcurrency}`);
    await _multiThreads.initThreadPool(navigator.hardwareConcurrency);
    console.log("initThreadPool");
    await _multiThreads.init_panic_hook();
    return _multiThreads;
}

async function fetchUint8Array(path: string): Promise<Uint8Array> {
    const buffer = await fetch(path).then(res => res.arrayBuffer());
    return new Uint8Array(buffer);
}


export async function fullProve(
    r1cs: string,
    wasm: string,
    csParams: string,
    cfCsParams: string,
    g16Pk: string,
    initState: string[],
    externalInputs: string[],
    nSteps: number
): Promise<number> {
    try {
        const r1csBytes = await fetchUint8Array(r1cs);
        const wasmBytes = await fetchUint8Array(wasm);
        const csParamsBytes = await fetchUint8Array(csParams);
        const cfCsParamsBytes = await fetchUint8Array(cfCsParams);
        const g16PkBytes = await fetchUint8Array(g16Pk);
        const multiThreads = await initMultiThreads();
        const start = performance.now();
        const proof = multiThreads.full_prove(
            r1csBytes,
            wasmBytes,
            csParamsBytes,
            cfCsParamsBytes,
            g16PkBytes,
            initState,
            externalInputs,
            nSteps
        );
        console.log(`proof size: ${proof.length}`);
        console.log(proof);
        return performance.now() - start;
    } catch (e) {
        console.error(e);
        multiThreads = await _initMultiThreads();
        throw e;
    }
}

// export async function fetchWasm(wasm_path: string): Promise<Uint8Array> {
//     const wasmBuffer = await fetch(wasm_path).then(res => res.arrayBuffer());
//     return new Uint8Array(wasmBuffer);
// }

const exports = {
    initMultiThreads,
    fullProve
};
expose(exports);
export type Worker = typeof exports;
