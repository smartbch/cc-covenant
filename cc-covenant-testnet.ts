import path from 'path';
import { BITBOX } from 'bitbox-sdk';
import { compileFile } from 'cashc';
import { stringify } from '@bitauth/libauth';
import {  
  Contract, 
  SignatureTemplate, 
  HashType, 
  SignatureAlgorithm,
} from 'cashscript';

import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import { createElectrumTestnetProvider, rawTxToStr } from './utils/utils';

const bitbox = new BITBOX();
const rootSeed = bitbox.Mnemonic.toSeed('cc_covenant_v2_testnet');
const hdNode = bitbox.HDNode.fromSeed(rootSeed);

// operators
const operatorKeyPairs = [...Array(10).keys()]
    .map(x => bitbox.HDNode.derive(hdNode, x + 100))
    .map(n => bitbox.HDNode.toKeyPair(n));
const operatorWIFs = operatorKeyPairs.map(k => bitbox.ECPair.toWIF(k));
const operatorPbks = operatorKeyPairs.map(k => bitbox.ECPair.toPublicKey(k));
const operatorPubkeysHash = bitbox.Crypto.hash160(Buffer.concat(operatorPbks))

// monitors
const monitorKeyPairs = [...Array(3).keys()]
    .map(x => bitbox.HDNode.derive(hdNode, x + 200))
    .map(n => bitbox.HDNode.toKeyPair(n));
const monitorWIFs = monitorKeyPairs.map(k => bitbox.ECPair.toWIF(k));
const monitorPbks = monitorKeyPairs.map(k => bitbox.ECPair.toPublicKey(k));
const monitorPubkeysHash = bitbox.Crypto.hash160(Buffer.concat(monitorPbks))

const artifact = compileFile(path.join(__dirname, 'cc-covenant-testnet.cash'));

const provider = createElectrumTestnetProvider();

yargs(hideBin(process.argv))
  .command('print-covenant-info', 'show covenant info', (yargs: any) => {
    return yargs
      .option('verbose', {required: false, type: 'boolean', default: true})
      ;
  }, async (argv: any) => {
    printKeys(argv.verbose);
    printContractInfo(argv.verbose);
  })
  .command('list-cc-utxo', 'show cc-UTXOs', (yargs: any) => {
    return yargs;
  }, async (argv: any) => {
    await listUTXOs();
  })
  .command('redeem-by-user', 'redeem cc-UTXO by user', (yargs: any) => {
    return yargs
      .option('to',     {required: true, type: 'string', description: 'receiver address'})
      .option('utxo',   {required: true, type: 'string', description: 'txid:vout'})
      .option('txfee',  {required: true, type: 'number', description: 'tx fee'})
      .option('dryrun', {required: false, type: 'boolean', default: false})
      ;
  }, async (argv: any) => {
    await redeemByUser(argv.to, argv.utxo, argv.txfee, argv.dryrun);
  })
  .command('redeem-all', 'redeem all cc-UTXOs', (yargs: any) => {
    return yargs
      .option('to',     {required: true, type: 'string', description: 'receiver address'})
      .option('txfee',  {required: true, type: 'number', description: 'tx fee'})
      ;
  }, async (argv: any) => {
      const contract = createContract();
      let utxos = await contract.getUtxos();
      console.log('addr:', contract.address);
      console.log('UTXOs:', utxos.length);

      for (const utxo of utxos) {
        if (utxo.satoshis < argv.txfee) {
          continue;
        }

        console.log('redeeming', utxo, '...');
        await redeemByUser(argv.to, `${utxo.txid}:${utxo.vout}`, argv.txfee, false);
      }
  })
  .command('convert-by-operators', 'convert cc-UTXO by operators', (yargs: any) => {
    return yargs
      .option('new-operator-pubkeys-hash', {required: true, type: 'string', description: '20-bytes hex'})
      .option('new-monitor-pubkeys-hash',  {required: true, type: 'string', description: '20-bytes hex'})
      .option('to',     {required: true, type: 'string', description: 'cc-covenant address'})
      .option('utxo',   {required: true, type: 'string', description: 'txid:vout'})
      .option('txfee',  {required: true, type: 'number', description: 'tx fee'})
      .option('dryrun', {required: false, type: 'boolean', default: false})
      ;
  }, async (argv: any) => {
    await convertByOperators(argv.utxo, argv.txfee, argv.to, 
        argv.newOperatorPubkeysHash, argv.newMonitorPubkeysHash, argv.dryrun);
  })
  .command('convert-by-monitors', 'convert cc-UTXO by monitors', (yargs: any) => {
    return yargs
      .option('new-operator-pubkeys-hash', {required: true, type: 'string', description: '20-bytes hex'})
      .option('to',       {required: true, type: 'string', description: 'new cc-covenant address'})
      .option('utxo',     {required: true, type: 'string', description: 'txid:vout'})
      .option('txfee',    {required: true, type: 'number', description: 'tx fee'})
      .option('fee-utxo', {required: true, type: 'string', description: 'txid:vout'})
      .option('fee-wif',  {required: true, type: 'string', description: 'key of fee provider in WIF'})
      .option('dryrun',   {required: false, type: 'boolean', default: false})
      ;
  }, async (argv: any) => {
    await convertByMonitors(argv.utxo, argv.to, argv.newOperatorPubkeysHash, 
        argv.feeUtxo, argv.feeWif, argv.txfee, argv.dryrun);
  })
  .strictCommands()
  .argv;

function printKeys(verbose: boolean) {
  if (verbose) {
    // console.log('operatorWIFs:', operatorWIFs.map(x => x.toString('hex')));
    // console.log('operatorPbks:', operatorPbks.map(x => x.toString('hex')));
    const ops = [];
    for (let i = 0; i < operatorWIFs.length; i++) {
      ops.push({
        WIF: operatorWIFs[i].toString('hex'),
        PBK: operatorPbks[i].toString('hex'),
      })
    }
    console.log('operators:');
    console.table(ops);
  }
  if (verbose) {
    // console.log('monitorWIFs:', monitorWIFs.map(x => x.toString('hex')));
    // console.log('monitorPbks:', monitorPbks.map(x => x.toString('hex')));
    const mos = [];
    for (let i = 0; i < monitorWIFs.length; i++) {
      mos.push({
        WIF: monitorWIFs[i].toString('hex'),
        PBK: monitorPbks[i].toString('hex'),
      })
    }
    console.log('monitors:');
    console.table(mos);
  }
  console.log('operatorPubkeysHash:', operatorPubkeysHash.toString('hex'));
  console.log('monitorPubkeysHash :', monitorPubkeysHash.toString('hex'));
}

function createContract() {
  const args = [monitorPubkeysHash, operatorPubkeysHash];
  const contract = new Contract(artifact, args, provider);
  return contract;
}

function printContractInfo(verbose: boolean) {
  const contract = createContract();
  if (verbose) {
    console.log("redeemScriptHex:", contract.getRedeemScriptHex());
  }
  console.log('redeemScriptHash:', bitbox.Crypto.hash160(Buffer.from(contract.getRedeemScriptHex(), 'hex')).toString('hex'));
  console.log('cashAddr:', contract.address);
  if (verbose) {
    console.log('oldAddr:', bitbox.Address.toLegacyAddress(contract.address));
  }
}

async function listUTXOs() {
  const contract = createContract();
  const utxos = await contract.getUtxos();
  const sum = utxos.reduce((partialSum, utxo) => partialSum + utxo.satoshis / 10**8, 0);
  console.log('addr:', contract.address);
  console.log('UTXOs:', utxos.length);
  console.log('balance:', sum);
  console.table(utxos);
}

async function redeemByUser(toAddr: string,
                            txIdVout: string,
                            txFee: number,
                            dryRun: boolean): Promise<void> {
  console.log('redeemByUser...');
  console.log('toAddr:', toAddr);
  console.log('txIdVout:', txIdVout);
  console.log('txFee:', txFee);
  await redeemOrConvert(toAddr, txIdVout, txFee, '', '', dryRun);
}

async function convertByOperators(txIdVout: string,
                                  txFee: number,
                                  newCovenantAddr: string,
                                  newOperatorPbukeysHash: string,
                                  newMonitorPubkeysHash: string,
                                  dryRun: boolean): Promise<void> {
  console.log('convertByOperators...');
  console.log('newCovenantAddr:', newCovenantAddr);
  console.log('newOperatorPbukeysHash:', newOperatorPbukeysHash);
  console.log('newMonitorPubkeysHash:', newMonitorPubkeysHash);
  await redeemOrConvert(newCovenantAddr, txIdVout, txFee, 
      newOperatorPbukeysHash, newMonitorPubkeysHash, dryRun);
}

async function redeemOrConvert(toAddr: string,
                               txIdVout: string,
                               txFee: number,
                               newOperatorPbukeysHash: string,
                               newMonitorPubkeysHash: string,
                               dryRun: boolean): Promise<void> {
  console.log('redeemOrConvert...');
  const contract = createContract();
  let utxos = await contract.getUtxos();
  console.log('contract UTXOs:', utxos);
  if (utxos.length == 0) {
    console.log("no UTXOs !");
    return;
  }

  const utxo = utxos.find(x => x.txid + ':' + x.vout == txIdVout);
  if (!utxo) {
    console.log("UTXO not found !");
    return;
  }
  const amt = utxo.satoshis - txFee;

  const operatorSigTmpls = operatorKeyPairs.slice(0, 7)
    .map(p => new SignatureTemplate(p, HashType.SIGHASH_ALL, SignatureAlgorithm.ECDSA));
  // console.log(operatorSigTmpls);

  const txBuilder = await contract.functions
    .redeemOrConvert(
      ...operatorSigTmpls,
      ...operatorPbks,
      newMonitorPubkeysHash,
      newOperatorPbukeysHash
    )
    .from([utxo])
    .to(toAddr, amt)
    .withHardcodedFee(txFee);

  if (dryRun) {
    const txHex = await txBuilder.build();
    console.log('txHex:', txHex);
    // const meepStr = await txBuilder.meep();
    // console.log('meep:', meepStr);
  } else {
    const tx = await txBuilder.send();
    console.log('transaction details:', stringify(tx));
  }
}

async function convertByMonitors(txIdVout: string,
                                 newCovenantAddr: string,
                                 newOperatorPbukeysHash: string,
                                 feeTxIdVout: string,
                                 feeWif: string,
                                 txFee: number,
                                 dryRun: boolean): Promise<void> {
  console.log('convertByMonitors...');

  const contract = createContract();
  let utxos = await contract.getUtxos();
  console.log('contract UTXOs:', utxos);
  if (utxos.length == 0) {
    console.log("no cc-UTXOs !");
    return;
  }

  const utxo = utxos.find(x => x.txid + ':' + x.vout == txIdVout);
  if (!utxo) {
    console.log("cc-UTXO not found !");
    return;
  }
  const amt = utxo.satoshis;

  const feeProviderPair = bitbox.ECPair.fromWIF(feeWif);
  const feeProviderAddr = bitbox.ECPair.toCashAddress(feeProviderPair);
  console.log('feeProviderAddr:', feeProviderAddr);

  let feeUtxos = await provider.getUtxos(feeProviderAddr);
  console.log('fee provider UTXOs:', feeUtxos)
  if (feeUtxos.length == 0) {
    console.log("no fee UTXOs !");
    return;
  }

  const feeUtxo = feeUtxos.find(x => x.txid + ':' + x.vout == feeTxIdVout);
  if (!feeUtxo) {
    console.log("fee UTXO not found !");
    return;
  }
  const changeAmt = feeUtxo.satoshis - txFee;
  if (changeAmt < 0) {
    console.log("not enough tx fee !");
    return;
  }

  (feeUtxo as any).template = new SignatureTemplate(feeProviderPair);

  const monotorSigTmpls = monitorKeyPairs.slice(0, 2)
    .map(p => new SignatureTemplate(p, HashType.SIGHASH_ALL, SignatureAlgorithm.ECDSA));
  // console.log(operatorSigTmpls);

  const txBuilder = await contract.functions
    .convertByMonitors(
      ...monotorSigTmpls,
      ...monitorPbks,
      newOperatorPbukeysHash
    )
    .from([utxo, feeUtxo])
    .to([{to: newCovenantAddr, amount: amt}])
    .withHardcodedFee(txFee)
    .withAge(34560);
  if (changeAmt > 0) {
    txBuilder.to(feeProviderAddr, changeAmt);
  }

  if (dryRun) {
    const txHex = await txBuilder.build();
    console.log('txHex:', txHex);
    // const meepStr = await txBuilder.meep();
    // console.log('meep:', meepStr);
  } else {
    const tx = await txBuilder.send();
    console.log('transaction details:', stringify(tx));
  }
}
