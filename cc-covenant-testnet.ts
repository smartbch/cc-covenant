import path from 'path';
import { BITBOX } from 'bitbox-sdk';
import { compileFile } from 'cashc';
import { stringify } from '@bitauth/libauth';
import { 
  ElectrumNetworkProvider, 
  Contract, 
  SignatureTemplate, 
  HashType, 
  SignatureAlgorithm,
} from 'cashscript';
import {
  ElectrumCluster,
  ElectrumTransport,
  ClusterOrder,
  RequestResponse,
} from 'electrum-cash';
import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'

const bitbox = new BITBOX();
const rootSeed = bitbox.Mnemonic.toSeed('cc_covenant_v2_testnet');
const hdNode = bitbox.HDNode.fromSeed(rootSeed);

// operators
const operatorKeyPairs = [...Array(10).keys()]
    .map(x => bitbox.HDNode.derive(hdNode, x + 100))
    .map(n => bitbox.HDNode.toKeyPair(n));
const operatorWIFs = operatorKeyPairs.map(k => bitbox.ECPair.toWIF(k));
const operatorPks = operatorKeyPairs.map(k => bitbox.ECPair.toPublicKey(k));
const operatorPubkeysHash = bitbox.Crypto.hash160(Buffer.concat(operatorPks))

// monitors
const monitorKeyPairs = [...Array(3).keys()]
    .map(x => bitbox.HDNode.derive(hdNode, x + 200))
    .map(n => bitbox.HDNode.toKeyPair(n));
const monitorWIFs = monitorKeyPairs.map(k => bitbox.ECPair.toWIF(k));
const monitorPks = monitorKeyPairs.map(k => bitbox.ECPair.toPublicKey(k));
const monitorPubkeysHash = bitbox.Crypto.hash160(Buffer.concat(monitorPks))

// alice
const aliceRootSeed = bitbox.Mnemonic.toSeed('alice');
const aliceHdNode = bitbox.HDNode.fromSeed(aliceRootSeed);
const aliceNode = bitbox.HDNode.derive(aliceHdNode, 1234);
const aliceKeyPair = bitbox.HDNode.toKeyPair(aliceNode);
const alicePubKey = bitbox.ECPair.toPublicKey(aliceKeyPair);
const alicePkh = bitbox.Crypto.hash160(alicePubKey);
const aliceCashAddr = bitbox.Address.hash160ToCash(alicePkh.toString('hex'), 0x6f);


const artifact = compileFile(path.join(__dirname, 'cc-covenant-testnet.cash'));

const electrum = new ElectrumCluster('CashScript Application', '1.4.1', 1, 2, ClusterOrder.PRIORITY);
electrum.addServer('blackie.c3-soft.com', 60002, ElectrumTransport.TCP_TLS.Scheme, false);
electrum.addServer('bch0.kister.net', 50002, ElectrumTransport.TCP_TLS.Scheme, false);
const provider = new ElectrumNetworkProvider('testnet', electrum);

yargs(hideBin(process.argv))
  .command('print-covenant-info', 'show covenant info', (yargs: any) => {
    return yargs;
  }, async (argv: any) => {
    printKeys();
    printContractInfo();
  })
  .command('list-cc-utxo', 'show cc-UTXOs', (yargs: any) => {
    return yargs;
  }, async (argv: any) => {
    await listUTXOs();
  })
  .command('redeem-by-user', 'redeem cc-UTXO by user', (yargs: any) => {
    return yargs
      .option('to',      {required: true, type: 'string', description: 'receiver address'})
      .option('utxo',    {required: true, type: 'string', description: 'txid:vout'})
      .option('txfee',   {required: true, type: 'number', description: 'tx fee'})
      ;
  }, async (argv: any) => {
    await redeemByUser(argv.to, argv.utxo, argv.txfee);
  })
  .command('convert-by-operators', 'convert cc-UTXO by operators', (yargs: any) => {
    return yargs
      .option('to',    {required: true, type: 'string', description: 'receiver address'})
      .option('utxo',  {required: true, type: 'string', description: 'txid:vout'})
      .option('txfee', {required: true, type: 'number', description: 'tx fee'})
      .option('new-operator-pubkeys-hash', {required: true, type: 'string', description: '20-bytes hex'})
      .option('new-monitor-pubkeys-hash',  {required: true, type: 'string', description: '20-bytes hex'})
      ;
  }, async (argv: any) => {
    await convertByOperators(argv.utxo, argv.txfee, argv.to, 
        argv.newOperatorPubkeysHash, argv.newMonitorPubkeysHash);
  })
  .command('convert-by-monitors', 'convert cc-UTXO by monitors', (yargs: any) => {
    return yargs
      .option('to',    {required: true, type: 'string', description: 'receiver address'})
      .option('utxo',  {required: true, type: 'string', description: 'txid:vout'})
      .option('txfee', {required: true, type: 'string', description: 'txid:vout'})
      .option('new-operator-pubkeys-hash', {required: true, type: 'string', description: '20-bytes hex'})
      ;
  }, async (argv: any) => {
    await convertByMonitors(argv.utxo, argv.txfee, argv.to, argv.newOperatorPubkeysHash);
  })
  .strictCommands()
  .argv;

function printKeys() {
  console.log('operatorWIFs:', operatorWIFs.map(x => x.toString('hex')));
  console.log('operatorPks:', operatorPks.map(x => x.toString('hex')));
  console.log('operatorPubkeysHash:', operatorPubkeysHash.toString('hex'));
  console.log('monitorWIFs:', monitorWIFs.map(x => x.toString('hex')));
  console.log('monitorPks:', monitorPks.map(x => x.toString('hex')));
  console.log('monitorPubkeysHash:', monitorPubkeysHash.toString('hex'));
}

function createContract() {
  const args = [monitorPubkeysHash, operatorPubkeysHash];
  const contract = new Contract(artifact, args, provider);
  return contract;
}

function printContractInfo() {
  const contract = createContract();
  console.log("redeemScriptHex:", contract.getRedeemScriptHex());
  console.log('>> redeemScriptHash:', bitbox.Crypto.hash160(Buffer.from(contract.getRedeemScriptHex(), 'hex')).toString('hex'));
  console.log('>> cash addr:', contract.address);
  console.log('>> old addr:', bitbox.Address.toLegacyAddress(contract.address));
}

async function listUTXOs() {
  const contract = createContract();
  let utxos = await contract.getUtxos();
  console.log('addr:', contract.address);
  console.log('UTXOs  :', utxos);
}

async function redeemByUser(toAddr: string,
                            txIdVout: string,
                            txFee: number): Promise<void> {
  console.log('redeemByUser...');
  console.log('toAddr:', toAddr);
  console.log('txIdVout:', txIdVout);
  console.log('txFee:', txFee);
  await redeemOrConvert(toAddr, txIdVout, txFee, '', '');
}

async function convertByOperators(txIdVout: string,
                                  txFee: number,
                                  newCovenantAddr: string,
                                  newOperatorPbukeysHash: string,
                                  newMonitorPubkeysHash: string): Promise<void> {
  console.log('convertByOperators...');
  console.log('newCovenantAddr:', newCovenantAddr);
  console.log('newOperatorPbukeysHash:', newOperatorPbukeysHash);
  console.log('newMonitorPubkeysHash:', newMonitorPubkeysHash);
  await redeemOrConvert(newCovenantAddr, txIdVout, txFee, 
      newOperatorPbukeysHash, newMonitorPubkeysHash);
}

async function redeemOrConvert(toAddr: string,
                               txIdVout: string,
                               txFee: number,
                               newOperatorPbukeysHash: string,
                               newMonitorPubkeysHash: string): Promise<void> {
  console.log('redeemOrConvert...');
  const contract = createContract();
  let utxos = await contract.getUtxos();
  console.log('contract UTXOs  :', utxos);
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
  const amt = utxo.satoshis - txFee;

  const operatorSigTmpls = operatorKeyPairs.slice(0, 7)
    .map(p => new SignatureTemplate(p, HashType.SIGHASH_ALL, SignatureAlgorithm.ECDSA));
  // console.log(operatorSigTmpls);

  const txBuilder = await contract.functions
    .redeemOrConvert(
      ...operatorSigTmpls,
      ...operatorPks,
      newMonitorPubkeysHash,
      newOperatorPbukeysHash
    )
    .from([utxo])
    .to(toAddr, amt)
    .withHardcodedFee(txFee);

  // const txHex = await txBuilder.build();
  // console.log('txHex:', txHex);
  // const meepStr = await txBuilder.meep();
  // console.log('meep:', meepStr);
  const tx = await txBuilder.send();
  console.log('transaction details:', stringify(tx));
}

async function convertByMonitors(txIdVout: string,
                                 feeTxIdVout: string,
                                 newCovenantAddr: string,
                                 newOperatorPbukeysHash: string): Promise<void> {
  console.log('convertByMonitors...');

  const contract = createContract();
  let utxos = await contract.getUtxos();
  console.log('contract UTXOs  :', utxos);
  if (utxos.length == 0) {
    console.log("no UTXOs !");
    return;
  }

  const utxo = utxos.find(x => x.txid + ':' + x.vout == txIdVout);
  if (!utxo) {
    console.log("UTXO not found !");
    return;
  }
  const amt = utxo.satoshis;

  let aliceUtxos = await provider.getUtxos(aliceCashAddr);
  console.log('alice UTXOs:', aliceUtxos)
  if (aliceUtxos.length == 0) {
    console.log("no UTXOs !");
    return;
  }

  const feeUtxo = aliceUtxos.find(x => x.txid + ':' + x.vout == feeTxIdVout);
  if (!feeUtxo) {
    console.log("UTXO not found !");
    return;
  }
  const txFee = feeUtxo.satoshis;
  (feeUtxo as any).template = new SignatureTemplate(aliceKeyPair);

  const monotorSigTmpls = monitorKeyPairs.slice(0, 2)
    .map(p => new SignatureTemplate(p, HashType.SIGHASH_ALL, SignatureAlgorithm.ECDSA));
  // console.log(operatorSigTmpls);

  const txBuilder = await contract.functions
    .convertByMonitors(
      ...monotorSigTmpls,
      ...monitorPks,
      newOperatorPbukeysHash
    )
    .from([utxo, feeUtxo])
    .to([{to: newCovenantAddr, amount: amt}])
    .withHardcodedFee(txFee);

  // const txHex = await txBuilder.build();
  // console.log('txHex:', txHex);
  // const meepStr = await txBuilder.meep();
  // console.log('meep:', meepStr);
  const tx = await txBuilder.send();
  console.log('transaction details:', stringify(tx));
}
