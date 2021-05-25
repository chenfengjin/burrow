import solc from 'solc_v5';
import { ABI } from './abi';
import { Contract } from './contract';

export type CompiledContract = {
  abi: ABI;
  // Required to deploy a contract
  bytecode?: string;
  // Required to submit an ABI when deploying a contract
  deployedBytecode?: string;
};

// Compile solidity source code
export function compile<T = any>(
  source: string,
  name: string,
  fatalErrorSeverity: 'error' | 'warning' = 'error',
): Contract<T> {
  const desc: solc.InputDescription = { language: 'Solidity', sources: {} };
  if (!desc.sources) {
    desc.sources = {};
  }
  desc.sources[name] = { content: source };
  desc.settings = { outputSelection: { '*': { '*': ['*'] } } };

  const json = solc.compile(JSON.stringify(desc));
  const compiled: solc.OutputDescription = JSON.parse(json);
  const fatalErrors = compiled.errors?.filter((err) => err.severity === fatalErrorSeverity) ?? [];
  if (fatalErrors.length) {
    throw new Error(fatalErrors.map((err) => err.formattedMessage).toString());
  }
  const contract = compiled.contracts[name][name];
  return new Contract(
    getCompiledCode(contract),
    Object.entries(compiled.contracts[name])
      .filter(([n]) => n !== name)
      .map(([n, c]) => getCompiledCode(c)),
  );
}

function getCompiledCode(contract: solc.Contract): Required<CompiledContract> {
  return {
    abi: contract.abi,
    bytecode: contract.evm.bytecode.object,
    deployedBytecode: contract.evm.deployedBytecode.object,
  };
}
