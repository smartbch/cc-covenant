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
import ElectrumNetworkProvider2 from './_ElectrumNetworkProvider';

// https://1209k.com/bitcoin-eye/ele.php?chain=tbch
export function createElectrumTestnetProvider() {
  // Initialise a 1-of-2 Electrum Cluster with 2 hardcoded servers
  const electrum = new ElectrumCluster('CashScript Application', '1.4.1', 1, 2, ClusterOrder.PRIORITY);
  electrum.addServer('blackie.c3-soft.com', 60002, ElectrumTransport.TCP_TLS.Scheme, false);
  electrum.addServer('tbch.loping.net', 60002, ElectrumTransport.TCP_TLS.Scheme, false);
  // electrum.addServer('testnet.bitcoincash.network', 60002, ElectrumTransport.TCP_TLS.Scheme, false);

  // Initialise a network provider for network operations on TESTNET
  return new ElectrumNetworkProvider('testnet3', electrum);
}

export function createElectrumTestnetProvider2() {
  // Initialise a 1-of-2 Electrum Cluster with 2 hardcoded servers
  const electrum = new ElectrumCluster('CashScript Application', '1.4.1', 1, 2, ClusterOrder.PRIORITY);
  electrum.addServer('blackie.c3-soft.com', 60002, ElectrumTransport.TCP_TLS.Scheme, false);
  electrum.addServer('tbch.loping.net', 60002, ElectrumTransport.TCP_TLS.Scheme, false);
  // electrum.addServer('testnet.bitcoincash.network', 60002, ElectrumTransport.TCP_TLS.Scheme, false);

  // Initialise a network provider for network operations on TESTNET
  return new ElectrumNetworkProvider2('testnet3', electrum);
}

export function rawTxToStr(txid: string, hex: string) {
  const libauthTx = decodeTransaction(hexToBin(hex)) as LibauthTx;
  return stringify({ ...libauthTx, txid, hex });
}

export function asciiToHex(str: string) {
  const arr1 = [];
  for (let n = 0, l = str.length; n < l; n ++) {
    let hex = Number(str.charCodeAt(n)).toString(16);
    arr1.push(hex);
   }
  return arr1.join('');
}
