/** @type {import('ts-jest').JestConfigWithTsJest} */
export default {
  preset: "ts-jest/presets/js-with-ts-esm",
  // globals: {
  //   "ts-jest": {
  //     useESM: true
  //   }
  // },
  testEnvironment: 'jest-environment-jsdom',
  moduleFileExtensions: ["ts", "tsx", "js"],
  // transform: {
  //   "^.+\\.m?[tj]sx?$": [
  //     "ts-jest",
  //     {
  //       tsconfig: "<rootDir>/tsconfig.json",
  //     },
  //   ],
  // }
};