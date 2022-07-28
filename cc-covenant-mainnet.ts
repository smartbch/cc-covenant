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

// Initialise BITBOX
const bitbox = new BITBOX();

// Initialise HD node
const rootSeed = bitbox.Mnemonic.toSeed('cc_covenant_v2_testnet');
const hdNode = bitbox.HDNode.fromSeed(rootSeed);

const monitorPks = [...Array(3).keys()]
  .map(x => bitbox.HDNode.derive(hdNode, x))
  .map(n => bitbox.HDNode.toKeyPair(n))
  .map(k => bitbox.ECPair.toPublicKey(k));
console.log('monitorPks:', monitorPks.map(x => x.toString('hex')));

const monitorPubkeysHash = bitbox.Crypto.hash160(Buffer.concat(monitorPks))
console.log('monitorPubkeysHash:', monitorPubkeysHash.toString('hex'));

const operatorPks = [...Array(10).keys()]
  .map(x => bitbox.HDNode.derive(hdNode, x + 100))
  .map(n => bitbox.HDNode.toKeyPair(n))
  .map(k => bitbox.ECPair.toPublicKey(k));
console.log('operatorPks:', operatorPks.map(x => x.toString('hex')));

const operatorPubkeysHash = bitbox.Crypto.hash160(Buffer.concat(operatorPks))
console.log('operatorPubkeysHash:', operatorPubkeysHash.toString('hex'));

const provider = new ElectrumNetworkProvider('testnet');

const artifact = compileFile(path.join(__dirname, 'cc-covenant-mainnet.cash'));
const args = [operatorPubkeysHash, monitorPubkeysHash];
const contract = new Contract(artifact, args, provider);
console.log("redeemScriptHex:", contract.getRedeemScriptHex());
console.log('>> redeemScriptHash:', bitbox.Crypto.hash160(Buffer.from(contract.getRedeemScriptHex(), 'hex')).toString('hex'));
console.log('>> cash addr:', contract.address);
console.log('>> old addr:', bitbox.Address.toLegacyAddress(contract.address));


redeem();

async function redeem(): Promise<void> {
  let utxos = await contract.getUtxos();
  console.log('contract UTXOs  :', utxos);
  if (utxos.length == 0) {
    console.log("no UTXOs !");
    return;
  }

  const alicePKH = '99c7e0b48a05cd6024b22cd490fcee30aa51d862';
  const aliceAddr = 'bchtest:qzvu0c953gzu6cpykgkdfy8uacc255wcvgmp7ekj7y';

  const utxo = utxos[0];
  const txFee = 4000;
  const amt = utxo.satoshis - txFee;

  const operatorSigTmpls = [...Array(6).keys()]
    .map(x => bitbox.HDNode.derive(hdNode, x + 100))
    .map(n => bitbox.HDNode.toKeyPair(n))
    .map(p => new SignatureTemplate(p, HashType.SIGHASH_ALL, SignatureAlgorithm.ECDSA));
  // console.log(operatorSigTmpls);

  const tx = await contract.functions
    .redeemOrConvert(
      ...operatorSigTmpls,
      ...operatorPks,
      alicePKH,
      true,
    )
    .from([utxo])
    .to(aliceAddr, amt)
    .withHardcodedFee(txFee)
    .send();
  console.log('transaction details:', stringify(tx));
}
