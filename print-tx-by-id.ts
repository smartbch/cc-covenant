import { ElectrumNetworkProvider } from 'cashscript';
import {
  hexToBin,
  decodeTransaction,
  Transaction as LibauthTransaction,
  stringify,
} from '@bitauth/libauth';
import {
  ElectrumCluster,
  ElectrumTransport,
  ClusterOrder,
  RequestResponse,
} from 'electrum-cash';

run();

async function run(): Promise<void> {
  if (process.argv.length < 3) {
    console.log('Usage: ts-node print-tx-by-id.ts <txid>');
    return;
  }

  const txid = process.argv[2];
  console.log('txid:', txid);

  const electrum = new ElectrumCluster('CashScript Application', '1.4.1', 1, 2, ClusterOrder.PRIORITY);
  electrum.addServer('blackie.c3-soft.com', 60002, ElectrumTransport.TCP_TLS.Scheme, false);
  electrum.addServer('bch0.kister.net', 50002, ElectrumTransport.TCP_TLS.Scheme, false);
  const provider = new ElectrumNetworkProvider('testnet', electrum);

  const hex = await provider.getRawTransaction(txid);
  // console.log('hex:', hex);

  const libauthTransaction = decodeTransaction(hexToBin(hex)) as LibauthTransaction;
  const tx = { ...libauthTransaction, txid, hex };
  console.log('tx details:', stringify(tx));
}
