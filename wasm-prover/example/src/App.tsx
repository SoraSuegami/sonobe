import React, { useEffect, useState } from 'react';
import { wrap } from 'comlink';
import { fullProve } from './worker';
// import { fetchWasm } from './worker';

const worker = new Worker(new URL('./worker', import.meta.url), {
  name: 'worker',
  type: 'module',
});
const workerApis = wrap<import('./worker').Worker>(worker);

const host = "http://localhost:3000";

async function f(id: number) {
  const time = await fullProve(
    `${host}/with_external_inputs.r1cs`,
    `${host}/with_external_inputs.wasm`,
    `${host}/cs_params.bin`,
    `${host}/cf_cs_params.bin`,
    `${host}/g16_pk.bin`,
    ["1"],
    [
      "6", "7", "8", "9", "10", "11", "12", "13", "14", "15",
      "6", "7", "8", "9", "10", "11", "12", "13", "14", "15",
    ],
    10
  );
  console.log(time);
}

function App() {
  // const [multiThreads, setMultiThreads] = useState<MultiThreads | null>(null);
  const [results, setResults] = useState<{ [key: number]: string }>({});


  // useEffect(() => {
  //   const init = async () => {
  //     console.log("hi?");
  //     const multiThreads = await workerApis.initMultiThreads();
  //     console.log(multiThreads);
  //     console.log("hi");
  //     setMultiThreads(multiThreads);
  //     console.log("bye");
  //   };
  //   init();
  // }, []);

  const handleClick = async (id: number) => {
    // console.log(multiThreads);
    // if (multiThreads == null) {
    //   throw new Error("multiThreads is null");
    // }
    setResults(prev => ({ ...prev, [id]: "Proving..." }));
    try {
      const result = await f(id);
      // setResults(prev => ({ ...prev, [id]: result }));
    } catch (e: any) {
      // setResults(prev => ({ ...prev, [id]: `Error: ${e.message}` }));
    }
  };

  return (
    <div className="App">
      <p style={{ height: '50px' }} ></p>
      <button onClick={() => handleClick(0)}>Prove</button>
      {/* {listData.map((item, idx) => (
        <div key={item.id}>
          <p>{item.description}</p>
          <button onClick={() => handleClick(item.id)}>Prove</button>
          {results[item.id] && <p>{results[item.id]}</p>}
          {idx % 2 === 1 && <div style={{ height: '30px' }} />}
        </div>
      ))} */}
    </div>
  );
}

export default App;