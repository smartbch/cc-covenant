import { rawTxToStr } from '../utils/utils';

run();

async function run(): Promise<void> {
  if (process.argv.length < 3) {
    console.log('Usage: ts-node print-raw-tx.ts <txdata>');
    return;
  }

  let txHex = process.argv[2];
  if (txHex.startsWith("0x")) {
    txHex = txHex.substring(2);
  }

  // console.log('txHex:', txHex);
  console.log(rawTxToStr('?', txHex));
}
