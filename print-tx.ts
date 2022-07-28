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

  const txid = process.argv[2];
  console.log('txid:', txid);

  // const txid = 'b8bdff274da6150e43f7b10bed1a2a21e2d74676ac2dc16e5ee3fee897f54c98';
  const hex = await provider.getRawTransaction(txid);
  console.log(hex);

  const libauthTransaction = decodeTransaction(hexToBin(hex)) as LibauthTransaction;
  const tx = { ...libauthTransaction, txid, hex };
  console.log(stringify(tx));
}
