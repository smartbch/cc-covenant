import { ElectrumNetworkProvider } from 'cashscript';
import {
  hexToBin,
  decodeTransaction,
  Transaction as LibauthTransaction,
  stringify,
} from '@bitauth/libauth';

run();

async function run(): Promise<void> {
  const provider = new ElectrumNetworkProvider('testnet');

  let txHex = process.argv[2];
  if (txHex.startsWith("0x")) {
    txHex = txHex.substring(2);
  }
  // console.log('txHex:', txHex);

  const libauthTransaction = decodeTransaction(hexToBin(txHex)) as LibauthTransaction;
  const tx = { ...libauthTransaction, txHex };
  console.log(stringify(tx));
}
