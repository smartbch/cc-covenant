import {
  ElectrumCluster,
  ElectrumTransport,
  ClusterOrder,
} from 'electrum-cash';
import {
  hexToBin,
  decodeTransaction,
  Transaction as LibauthTx,
  stringify,
} from '@bitauth/libauth';
import { ElectrumNetworkProvider } from 'cashscript';

export function createElectrumTestnetProvider() {
  // Initialise a 1-of-2 Electrum Cluster with 2 hardcoded servers
  const electrum = new ElectrumCluster('CashScript Application', '1.4.1', 1, 2, ClusterOrder.PRIORITY);
  electrum.addServer('blackie.c3-soft.com', 60002, ElectrumTransport.TCP_TLS.Scheme, false);
  // electrum.addServer('tbch.loping.net', 60002, ElectrumTransport.TCP_TLS.Scheme, false);
  electrum.addServer('testnet.bitcoincash.network', 60002, ElectrumTransport.TCP_TLS.Scheme, false);

  // Initialise a network provider for network operations on TESTNET
  const provider = new ElectrumNetworkProvider('testnet', electrum);

  return provider;
}

export function rawTxToStr(txid: string, hex: string) {
  const libauthTx = decodeTransaction(hexToBin(hex)) as LibauthTx;
  return stringify({ ...libauthTx, txid, hex });
}
