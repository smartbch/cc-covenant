import { createElectrumTestnetProvider, rawTxToStr } from '../utils/utils';

run();

async function run(): Promise<void> {
  if (process.argv.length < 3) {
    console.log('Usage: ts-node print-tx-by-id.ts <txid>');
    return;
  }

  const txid = process.argv[2];
  console.log('txid:', txid);

  const provider = createElectrumTestnetProvider();
  const hex = await provider.getRawTransaction(txid);
  console.log('tx details:', rawTxToStr(txid, hex));
}
