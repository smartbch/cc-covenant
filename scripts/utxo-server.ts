import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'

import express from "express";
import cors from "cors";

import { BITBOX } from 'bitbox-sdk';
import { asciiToHex, createElectrumTestnetProvider2 } from '../utils/utils';


const mnemonic = process.env.MNEMONIC || 'faucet';
const port = process.env.PORT || 8887;
const ccCovenantAddr = 'bchtest:pp4d87q4y0y84gtlrhaqsfcu74akya7f3c54m3nhzk';
const amt = 200000;
const txFee = 1000;


// Initialise BITBOX
const bitbox = new BITBOX({});

// Initialise HD node
const rootSeed = bitbox.Mnemonic.toSeed(mnemonic);
const hdNode = bitbox.HDNode.fromSeed(rootSeed);
const faucetNode = bitbox.HDNode.derive(hdNode, 1234);
const faucetKeyPair = bitbox.HDNode.toKeyPair(faucetNode);
const faucetPubKey = bitbox.ECPair.toPublicKey(faucetKeyPair);
const faucetPkh = bitbox.Crypto.hash160(faucetPubKey);
const faucetCashAddr = bitbox.Address.hash160ToCash(faucetPkh.toString('hex'), 0x6f);

// Initialise a network provider for network operations on TESTNET
const provider = createElectrumTestnetProvider2();


const app = express();
app.use(cors());

app.get('/info', async (req, res) => {
  res.json({
    address: faucetCashAddr,
  });
});

app.get('/history', async (req, res) => {
  const covenantAddr = req.query.covenantAddr as string || ccCovenantAddr;
  const history = await provider.getHistory(covenantAddr);
  res.json(history);
});

app.get('/tx', async (req, res) => {
  const txid = req.query.id as string;
  const tx = await provider.getTx(txid);
  res.json(tx);
});

app.get('/utxos', async (req, res) => {
  const utxos = await provider.getUtxos(faucetCashAddr);
  res.json(utxos);
});

app.get('/spend', async (req, res) => {
  const covenantAddr = req.query.covenantAddr || ccCovenantAddr;
  const receiverAddr = req.query.receiverAddr as string;
  console.log('spend, covenantAddr:', covenantAddr, 'receiverAddr:', receiverAddr);

  if (!receiverAddr) {
    res.json({success: false, error: 'missing param: receiverAddr'});
    return;
  }

  let utxos = await provider.getUtxos(faucetCashAddr);
  utxos = utxos.filter(x => x.satoshis > amt);
  if (utxos.length == 0) {
    res.json({success: false, error: 'no spendable UTXOs'});
    return;
  }

  const utxo = utxos[0];
  const txBuilder = new bitbox.TransactionBuilder('testnet');
  txBuilder.addInput(utxo.txid, utxo.vout);
  txBuilder.addOutput(ccCovenantAddr, amt);

  const change = utxo.satoshis - amt - txFee;
  if (change > 0) {
    txBuilder.addOutput(faucetCashAddr, change);
  }

  const retDataHex = asciiToHex(receiverAddr);
  // console.log('retDataHex:', retDataHex);
  const retDataBuf = Buffer.from(retDataHex, 'hex');
  const nullDataScript = bitbox.Script.nullData.output.encode(retDataBuf);
  // console.log('nullDataScript:', nullDataScript);
  txBuilder.addOutput(nullDataScript, 0);

  // Sign the transaction with the HD node.
  let redeemScript
  txBuilder.sign(
    0,
    faucetKeyPair,
    redeemScript,
    txBuilder.hashTypes.SIGHASH_ALL,
    utxo.satoshis
  );

  // build tx
  const tx = txBuilder.build();
  // output rawhex
  const hex = tx.toHex();
  // console.log('rawTx:', hex);
  // res.json({hex: hex});
  // return;

  // Broadcast transation to the network
  console.log('broadcasting tx ...');
  const txid = await provider.sendRawTransaction(hex);
  // console.log(`Transaction ID: ${txid}`);

  // const libauthTx = decodeTransaction(hexToBin(hex)) as LibauthTx;
  // console.log('tx details:', stringify({ ...libauthTx, txid, hex }));
  res.json({success: true, txid: txid});
});

app.listen(port, () => {
  console.log("HTTP server listening at port %s", port);
});
