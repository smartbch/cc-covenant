import {
  hexToBin,
  decodeTransaction,
  Transaction as LibauthTransaction,
  stringify,
} from '@bitauth/libauth';

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

  const libauthTransaction = decodeTransaction(hexToBin(txHex)) as LibauthTransaction;
  const tx = { ...libauthTransaction, txHex };
  console.log(stringify(tx));
}
