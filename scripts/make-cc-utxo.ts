import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import { BITBOX } from 'bitbox-sdk';
import { 
  createElectrumTestnetProvider, 
  rawTxToStr,
  asciiToHex
} from '../utils/utils';

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

// Initialise a network provider for network operations on TESTNET
const provider = createElectrumTestnetProvider();

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
    await spendUTXO(argv.to, toArr(argv.utxo), toArr(argv.retdata), argv.amt, argv.txfee);
  })
  .strictCommands()
  .argv;

function toArr(arg: string | string[]): string[] {
  switch (typeof arg) {
  case 'string':
    return [arg as string];
  case 'object': // array
    return arg as string[];
  default:
    return [];
  }
}

async function printUserInfo() {
  console.log('WIF     :', userKeyPair.toWIF());
  console.log('Pubkey  :', userPubKey.toString('hex'));
  console.log('PKH     :', userPkh.toString('hex'));
  console.log('CashAddr:', userCashAddr);

  console.log('quering UTXOs ...');
  const utxos = await provider.getUtxos(userCashAddr);
  const sum = utxos.reduce((partialSum, utxo) => partialSum + utxo.satoshis / 10**8, 0);
  console.log('UTXOs:', utxos.length);
  console.log('balance:', sum);
  console.table(utxos);
}

async function spendUTXO(toAddr: string,
                         txIdVout: string[],
                         retData: string[],
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

  utxos = utxos.filter(x => txIdVout.indexOf(x.txid + ':' + x.vout) >= 0);
  if (utxos.length == 0) {
    console.log("UTXO not found !");
    return;
  }

  const txBuilder = new bitbox.TransactionBuilder('testnet');

  let totalAmt = 0;
  for (const utxo of utxos) {
    txBuilder.addInput(utxo.txid, utxo.vout);
    totalAmt += utxo.satoshis;
  }

  txBuilder.addOutput(toAddr, amt);
  const change = totalAmt - amt - txFee;
  if (change > 0) {
    txBuilder.addOutput(userCashAddr, change);
  }

  for (const dataStr of retData) {
    if (dataStr != 'no') {
      const retDataHex = asciiToHex(dataStr);
      // console.log('retDataHex:', retDataHex);
      const retDataBuf = Buffer.from(retDataHex, 'hex');
      const nullDataScript = bitbox.Script.nullData.output.encode(retDataBuf);
      // console.log('nullDataScript:', nullDataScript);
      txBuilder.addOutput(nullDataScript, 0);
    }
  }

  // Sign the transaction with the HD node.
  utxos.forEach((utxo, idx) => {
    let redeemScript
    txBuilder.sign(
      idx,
      userKeyPair,
      redeemScript,
      txBuilder.hashTypes.SIGHASH_ALL,
      utxo.satoshis,
    );
  });

  // build tx
  const tx = txBuilder.build();
  // output rawhex
  const hex = tx.toHex();
  // console.log('rawTx:', hex);

  // Broadcast transation to the network
  console.log('broadcasting tx ...');
  const txid = await provider.sendRawTransaction(hex);
  // console.log(`Transaction ID: ${txid}`);

  console.log('tx details:', rawTxToStr(txid, hex));
}
