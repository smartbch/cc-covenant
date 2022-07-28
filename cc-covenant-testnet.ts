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


printKeys();
console.log('----------');
printContractInfo();
// console.log('----------');
// redeem();

function printKeys() {
  const operatorWIFs = getOperatorWIFs();
  console.log('operatorWIFs:', operatorWIFs.map(x => x.toString('hex')));

  const operatorPks = getOperatorPubKeys();
  console.log('operatorPks:', operatorPks.map(x => x.toString('hex')));

  const operatorPubkeysHash = bitbox.Crypto.hash160(Buffer.concat(operatorPks))
  console.log('operatorPubkeysHash:', operatorPubkeysHash.toString('hex'));

  const monitorWIFs = getMonitorWIFs();
  console.log('monitorWIFs:', monitorWIFs.map(x => x.toString('hex')));

  const monitorPks = getMonitorPubKeys();
  console.log('monitorPks:', monitorPks.map(x => x.toString('hex')));

  const monitorPubkeysHash = bitbox.Crypto.hash160(Buffer.concat(monitorPks))
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
  const args = [getOperatorPubkeysHash(), getMonitorPubkeysHash()];
  const contract = new Contract(artifact, args, provider);
  return contract;
}

function getOperatorPubkeysHash() {
  const pks = getOperatorPubKeys();
  return bitbox.Crypto.hash160(Buffer.concat(pks));
}
function getMonitorPubkeysHash() {
  const pks = getMonitorPubKeys();
  return bitbox.Crypto.hash160(Buffer.concat(pks));
}

function getOperatorWIFs() {
  return [...Array(3).keys()]
    .map(x => bitbox.HDNode.derive(hdNode, x + 100))
    .map(n => bitbox.HDNode.toKeyPair(n))
    .map(k => bitbox.ECPair.toWIF(k));
}
function getMonitorWIFs() {
  return [...Array(3).keys()]
    .map(x => bitbox.HDNode.derive(hdNode, x + 200))
    .map(n => bitbox.HDNode.toKeyPair(n))
    .map(k => bitbox.ECPair.toWIF(k));
}

function getOperatorPubKeys() {
  return [...Array(3).keys()]
    .map(x => bitbox.HDNode.derive(hdNode, x + 100))
    .map(n => bitbox.HDNode.toKeyPair(n))
    .map(k => bitbox.ECPair.toPublicKey(k));
}
function getMonitorPubKeys() {
  return [...Array(3).keys()]
    .map(x => bitbox.HDNode.derive(hdNode, x + 200))
    .map(n => bitbox.HDNode.toKeyPair(n))
    .map(k => bitbox.ECPair.toPublicKey(k));
}

async function redeem(): Promise<void> {
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
  const txFee = 4000;
  const amt = utxo.satoshis - txFee;

  const operatorPks = [...Array(3).keys()]
    .map(x => bitbox.HDNode.derive(hdNode, x + 100))
    .map(n => bitbox.HDNode.toKeyPair(n))
    .map(k => bitbox.ECPair.toPublicKey(k));

  const operatorSigTmpls = [...Array(2).keys()]
    .map(x => bitbox.HDNode.derive(hdNode, x + 100))
    .map(n => bitbox.HDNode.toKeyPair(n))
    .map(p => new SignatureTemplate(p, HashType.SIGHASH_ALL, SignatureAlgorithm.ECDSA));
  // console.log(operatorSigTmpls);

  const txBuilder = await contract.functions
    .redeemOrConvert(
      ...operatorSigTmpls,
      ...operatorPks,
      alicePKH,
      true,
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
