import path from 'path';
import { BITBOX } from 'bitbox-sdk';
import { compileFile } from 'cashc';
import { stringify } from '@bitauth/libauth';
import { 
  ElectrumNetworkProvider, 
  Contract, 
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

const provider = new ElectrumNetworkProvider('mainnet');

const artifact = compileFile(path.join(__dirname, 'cc-covenant-mainnet.cash'));
const args = [monitorPubkeysHash, operatorPubkeysHash];
const contract = new Contract(artifact, args, provider);
console.log("redeemScriptHex:", contract.getRedeemScriptHex());
console.log('>> redeemScriptHash:', bitbox.Crypto.hash160(Buffer.from(contract.getRedeemScriptHex(), 'hex')).toString('hex'));
console.log('>> cash addr:', contract.address);
console.log('>> old addr:', bitbox.Address.toLegacyAddress(contract.address));
