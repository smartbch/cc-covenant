import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'

import { BITBOX } from 'bitbox-sdk';
import {
  ElectrumCluster,
  ElectrumTransport,
  ClusterOrder,
} from 'electrum-cash';
import { ElectrumNetworkProvider } from 'cashscript';
import {
  hexToBin,
  decodeTransaction,
  Transaction as LibauthTx,
  stringify,
} from '@bitauth/libauth';


// Initialise BITBOX
const bitbox = new BITBOX({});

// Initialise HD node
const mnemonic     = process.env.MNEMONIC || 'alice';
const rootSeed     = bitbox.Mnemonic.toSeed(mnemonic);
const hdNode       = bitbox.HDNode.fromSeed(rootSeed);
const userNode     = bitbox.HDNode.derive(hdNode, 1234);
const userKeyPair  = bitbox.HDNode.toKeyPair(userNode);
const userPubKey   = bitbox.ECPair.toPublicKey(userKeyPair);
const userPkh      = bitbox.Crypto.hash160(userPubKey);
const userCashAddr = bitbox.Address.hash160ToCash(userPkh.toString('hex'), 0x6f);

// Initialise a 1-of-2 Electrum Cluster with 2 hardcoded servers
const electrum = new ElectrumCluster('CashScript Application', '1.4.1', 1, 2, ClusterOrder.PRIORITY);
electrum.addServer('blackie.c3-soft.com', 60002, ElectrumTransport.TCP_TLS.Scheme, false);
// electrum.addServer('tbch.loping.net', 60002, ElectrumTransport.TCP_TLS.Scheme, false);
electrum.addServer('testnet.bitcoincash.network', 60002, ElectrumTransport.TCP_TLS.Scheme, false);

// Initialise a network provider for network operations on TESTNET
const provider = new ElectrumNetworkProvider('testnet', electrum);

yargs(hideBin(process.argv))
  .command('list-utxo', 'show P2PKH address and UTXO set', (yargs: any) => {
    return yargs;
  }, async (argv: any) => {
    await printUserInfo();
  })
  .command('spend-utxo', 'spend utxo', (yargs: any) => {
    return yargs
      .option('to',      {required: true, type: 'string', description: 'receiver address'})
      .option('utxo',    {required: true, type: 'string', description: 'txid:vout'})
      .option('retdata', {required: false,type: 'string', description: 'return data'})
      .option('amt',     {required: true, type: 'number', description: 'amount'})
      .option('txfee',   {required: true, type: 'number', description: 'tx fee'})
      ;
  }, async (argv: any) => {
    await spendUTXO(argv.to, argv.utxo, argv.retdata, argv.amt, argv.txfee);
  })
  .strictCommands()
  .argv;

async function printUserInfo() {
  console.log('WIF     :', userKeyPair.toWIF());
  console.log('Pubkey  :', userPubKey.toString('hex'));
  console.log('PKH     :', userPkh.toString('hex'));
  console.log('CashAddr:', userCashAddr);

  console.log('quering UTXOs ...');
  const utxos = await provider.getUtxos(userCashAddr);
  console.log("utxos:", utxos);
}

async function spendUTXO(toAddr: string,
                         txIdVout: string,
                         retData: string,
                         amt: number,
                         txFee: number) {
  console.log('toAddr:', toAddr);
  console.log('txIdVout:', txIdVout);
  console.log('retData:', retData);
  console.log('amount:', amt);
  console.log('txFee:', txFee);

  console.log('quering unspent UTXOs ...');
  let utxos = await provider.getUtxos(userCashAddr);
  console.log('UTXOs:', utxos)
  if (utxos.length == 0) {
    console.log("no UTXOs !");
    return;
  }

  utxos = utxos.filter(x => x.txid + ':' + x.vout == txIdVout);
  if (utxos.length == 0) {
    console.log("UTXO not found !");
    return;
  }

  const utxo = utxos[0];
  const txBuilder = new bitbox.TransactionBuilder('testnet');
  txBuilder.addInput(utxo.txid, utxo.vout);
  txBuilder.addOutput(toAddr, amt);

  const change = utxo.satoshis - amt - txFee;
  if (change > 0) {
    txBuilder.addOutput(userCashAddr, change);
  }

  if (retData && retData != 'no') {
    const retDataHex = asciiToHex(retData);
    // console.log('retDataHex:', retDataHex);
    const retDataBuf = Buffer.from(retDataHex, 'hex');
    const nullDataScript = bitbox.Script.nullData.output.encode(retDataBuf);
    // console.log('nullDataScript:', nullDataScript);
    txBuilder.addOutput(nullDataScript, 0);
  }

  // Sign the transaction with the HD node.
  let redeemScript
  txBuilder.sign(
    0,
    userKeyPair,
    redeemScript,
    txBuilder.hashTypes.SIGHASH_ALL,
    utxo.satoshis
  );

  // build tx
  const tx = txBuilder.build();
  // output rawhex
  const hex = tx.toHex();
  // console.log('rawTx:', hex);

  // Broadcast transation to the network
  console.log('broadcasting tx ...');
  const txid = await provider.sendRawTransaction(hex);
  // console.log(`Transaction ID: ${txid}`);

  const libauthTx = decodeTransaction(hexToBin(hex)) as LibauthTx;
  console.log('tx details:', stringify({ ...libauthTx, txid, hex }));
}

function asciiToHex(str: string) {
  const arr1 = [];
  for (let n = 0, l = str.length; n < l; n ++) {
    let hex = Number(str.charCodeAt(n)).toString(16);
    arr1.push(hex);
   }
  return arr1.join('');
}
