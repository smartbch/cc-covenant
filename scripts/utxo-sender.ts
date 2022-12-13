import { randomBytes } from 'crypto';
import { BITBOX } from 'bitbox-sdk';
import { asciiToHex, createElectrumTestnetProvider } from '../utils/utils';


const mnemonic = process.env.MNEMONIC || 'utxo-sender';
const ccCovenantAddr = 'bchtest:pp4d87q4y0y84gtlrhaqsfcu74akya7f3c54m3nhzk';
const amt = 200000;
const txFee = 1000;


// Initialise BITBOX
const bitbox = new BITBOX({});

// Initialise HD node
const rootSeed = bitbox.Mnemonic.toSeed(mnemonic);
const hdNode = bitbox.HDNode.fromSeed(rootSeed);
const senderNode = bitbox.HDNode.derive(hdNode, 1234);
const senderKeyPair = bitbox.HDNode.toKeyPair(senderNode);
const senderPubKey = bitbox.ECPair.toPublicKey(senderKeyPair);
const senderPkh = bitbox.Crypto.hash160(senderPubKey);
const senderCashAddr = bitbox.Address.hash160ToCash(senderPkh.toString('hex'), 0x6f);

// Initialise a network provider for network operations on TESTNET
const provider = createElectrumTestnetProvider();

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

async function main() {
  console.log('addr:', senderCashAddr);
  while (true) {
    await send();
    await sleep(3600 * 1000);
  }
}

async function send() {
  const utxos = await provider.getUtxos(senderCashAddr);
  console.log('utxos:', utxos);

  const utxo = utxos.find(utxo => utxo.satoshis > amt + txFee);
  if (!utxo) {
    return;
  }

  const txBuilder = new bitbox.TransactionBuilder('testnet');
  txBuilder.addInput(utxo.txid, utxo.vout);
  txBuilder.addOutput(ccCovenantAddr, amt);

  const change = utxo.satoshis - amt - txFee;
  if (change > 0) {
    txBuilder.addOutput(senderCashAddr, change);
  }

  const receiverAddr = '0x' + randomBytes(20).toString('hex');
  console.log('receiverAddr:', receiverAddr);

  const retDataHex = asciiToHex(receiverAddr);
  const retDataBuf = Buffer.from(retDataHex, 'hex');
  const nullDataScript = bitbox.Script.nullData.output.encode(retDataBuf);
  txBuilder.addOutput(nullDataScript, 0);

  // Sign the transaction with the HD node.
  let redeemScript
  txBuilder.sign(
    0,
    senderKeyPair,
    redeemScript,
    txBuilder.hashTypes.SIGHASH_ALL,
    utxo.satoshis
  );

  const tx = txBuilder.build();
  const hex = tx.toHex();

  console.log('broadcasting tx ...');
  const txid = await provider.sendRawTransaction(hex);
  console.log('txid:', txid);
}

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
