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

const bitbox = new BITBOX();
const rootSeed = bitbox.Mnemonic.toSeed('cc_covenant_v2_testnet');
const hdNode = bitbox.HDNode.fromSeed(rootSeed);
const provider = new ElectrumNetworkProvider('testnet');
const artifact = compileFile(path.join(__dirname, 'cc-covenant-testnet.cash'));

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

printKeys();
console.log('----------');
printContractInfo();
console.log('----------');
// redeem();
// convertByOperators();

function printKeys() {
  console.log('operatorWIFs:', operatorWIFs.map(x => x.toString('hex')));
  console.log('operatorPks:', operatorPks.map(x => x.toString('hex')));
  console.log('operatorPubkeysHash:', operatorPubkeysHash.toString('hex'));
  console.log('monitorWIFs:', monitorWIFs.map(x => x.toString('hex')));
  console.log('monitorPks:', monitorPks.map(x => x.toString('hex')));
  console.log('monitorPubkeysHash:', monitorPubkeysHash.toString('hex'));
}

function printContractInfo() {
  const contract = createContract();
  console.log("redeemScriptHex:", contract.getRedeemScriptHex());
  console.log('>> redeemScriptHash:', bitbox.Crypto.hash160(Buffer.from(contract.getRedeemScriptHex(), 'hex')).toString('hex'));
  console.log('>> cash addr:', contract.address);
  console.log('>> old addr:', bitbox.Address.toLegacyAddress(contract.address));
}

function createContract() {
  const args = [monitorPubkeysHash, operatorPubkeysHash];
  const contract = new Contract(artifact, args, provider);
  return contract;
}

async function redeem(): Promise<void> {
  console.log('redeem...');
  const alicePKH = '99c7e0b48a05cd6024b22cd490fcee30aa51d862';
  const aliceAddr = 'bchtest:qzvu0c953gzu6cpykgkdfy8uacc255wcvgmp7ekj7y';

  const contract = createContract();
  let utxos = await contract.getUtxos();
  console.log('contract UTXOs  :', utxos);
  if (utxos.length == 0) {
    console.log("no UTXOs !");
    return;
  }

  const utxo = utxos[0];
  const txFee = 2000;
  const amt = utxo.satoshis - txFee;

  const operatorSigTmpls = operatorKeyPairs.slice(0, 7)
    .map(p => new SignatureTemplate(p, HashType.SIGHASH_ALL, SignatureAlgorithm.ECDSA));
  // console.log(operatorSigTmpls);

  const txBuilder = await contract.functions
    .redeemOrConvert(
      ...operatorSigTmpls,
      ...operatorPks,
      '',
      operatorPubkeysHash
    )
    .from([utxo])
    .to(aliceAddr, amt)
    .withHardcodedFee(txFee);

  // const txHex = await txBuilder.build();
  // console.log('txHex:', txHex);
  // const meepStr = await txBuilder.meep();
  // console.log('meep:', meepStr);
  const tx = await txBuilder.send();
  console.log('transaction details:', stringify(tx));
}

async function convertByOperators(): Promise<void> {
  console.log('convertByOperators...');

  const contract = createContract();
  let utxos = await contract.getUtxos();
  console.log('contract UTXOs  :', utxos);
  if (utxos.length == 0) {
    console.log("no UTXOs !");
    return;
  }

  const utxo = utxos[0];
  const txFee = 2000;
  const amt = utxo.satoshis - txFee;

  const operatorSigTmpls = operatorKeyPairs.slice(0, 7)
    .map(p => new SignatureTemplate(p, HashType.SIGHASH_ALL, SignatureAlgorithm.ECDSA));
  // console.log(operatorSigTmpls);

  const newOperatorsPbukeysHash = '57a158339cd184037a5b27d3033cb721713f27c3';
  const newCovenantAddr = 'bchtest:pzhzcadkj36luj9ptudg8z6j8r6vc49atqqhxjyaf3';

  const txBuilder = await contract.functions
    .redeemOrConvert(
      ...operatorSigTmpls,
      ...operatorPks,
      monitorPubkeysHash,
      newOperatorsPbukeysHash
    )
    .from([utxo])
    .to(newCovenantAddr, amt)
    .withHardcodedFee(txFee);

  // const txHex = await txBuilder.build();
  // console.log('txHex:', txHex);
  // const meepStr = await txBuilder.meep();
  // console.log('meep:', meepStr);
  const tx = await txBuilder.send();
  console.log('transaction details:', stringify(tx));
}

async function convertByMonitors(): Promise<void> {
  console.log('convertByMonitors...');

  const contract = createContract();
  let utxos = await contract.getUtxos();
  console.log('contract UTXOs  :', utxos);
  if (utxos.length == 0) {
    console.log("no UTXOs !");
    return;
  }

  const utxo = utxos[0];
  const txFee = 2000;
  const amt = utxo.satoshis - txFee;

  const monotorSigTmpls = monitorKeyPairs.slice(0, 2)
    .map(p => new SignatureTemplate(p, HashType.SIGHASH_ALL, SignatureAlgorithm.ECDSA));
  // console.log(operatorSigTmpls);

  const newOperatorsPbukeysHash = '57a158339cd184037a5b27d3033cb721713f27c3';
  const newCovenantAddr = 'bchtest:pzhzcadkj36luj9ptudg8z6j8r6vc49atqqhxjyaf3';

  const txBuilder = await contract.functions
    .convertByMonitors(
      ...monotorSigTmpls,
      ...monitorPks,
      monitorPubkeysHash,
      newOperatorsPbukeysHash
    )
    .from([utxo])
    .to([{to: newCovenantAddr, amount: amt}])
    .withHardcodedFee(txFee);

  // const txHex = await txBuilder.build();
  // console.log('txHex:', txHex);
  // const meepStr = await txBuilder.meep();
  // console.log('meep:', meepStr);
  const tx = await txBuilder.send();
  console.log('transaction details:', stringify(tx));
}
