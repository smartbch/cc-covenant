import { BITBOX } from 'bitbox-sdk';
import { ElectrumNetworkProvider } from 'cashscript';
import {
  ElectrumCluster,
  ElectrumTransport,
  ClusterOrder,
  RequestResponse,
} from 'electrum-cash';

run();

async function run(): Promise<void> {
  let rawTx = process.argv[2];
  if (rawTx.startsWith("0x")) {
    rawTx = rawTx.substring(2);
  }
  console.log('rawTx:', rawTx);

  // Initialise a 1-of-2 Electrum Cluster with 2 hardcoded servers
  const electrum = new ElectrumCluster('CashScript Application', '1.4.1', 1, 2, ClusterOrder.PRIORITY);
  electrum.addServer('blackie.c3-soft.com', 60002, ElectrumTransport.TCP_TLS.Scheme, false);
  electrum.addServer('bch0.kister.net', 50002, ElectrumTransport.TCP_TLS.Scheme, false);

  // Initialise a network provider for network operations on TESTNET
  const provider = new ElectrumNetworkProvider('testnet', electrum);

  // Broadcast transation to the network
  const broadcast = await provider.sendRawTransaction(rawTx);
  console.log(`Transaction ID: ${broadcast}`);
}
