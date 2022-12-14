import { BITBOX } from 'bitbox-sdk';
import { stringify } from '@bitauth/libauth';
import { 
  Contract, 
  SignatureTemplate, 
  ElectrumNetworkProvider,
} from 'cashscript';
import { compileFile } from 'cashc';
import path from 'path';
import { createElectrumTestnetProvider, rawTxToStr } from './utils/utils';

// Initialise BITBOX
const bitbox = new BITBOX();

// Initialise HD node and alice's keypair
const rootSeed = bitbox.Mnemonic.toSeed('smartBCH_faucet');
const hdNode = bitbox.HDNode.fromSeed(rootSeed);
const alice = bitbox.HDNode.toKeyPair(bitbox.HDNode.derive(hdNode, 0));

// Derive alice's public key and public key hash
const alicePk = bitbox.ECPair.toPublicKey(alice);
const alicePkh = bitbox.Crypto.hash160(alicePk);

// Initialise a network provider for network operations on TESTNET
const provider = createElectrumTestnetProvider();

// Compile the P2PKH contract to an artifact object
const artifact = compileFile(path.join(__dirname, 'p2pkh.cash'));

// Instantiate a new contract using the compiled artifact and network provider
// AND providing the constructor parameters (pkh: alicePkh)
const contract = new Contract(artifact, [alicePkh], provider);


run();

async function run(): Promise<void> {
  if (process.argv.length < 4) {
    console.log('Usage: ts-node p2pkh.ts <address> <amt> [op_return_data]');
    console.log('');
    await printInfo();
    return;
  }

  const addr = process.argv[2];
  const amt = process.argv[3];
  let opRetData = "";
  if (process.argv.length > 4) {
    opRetData = process.argv[4];
  }

  await sendTo(addr, +amt, opRetData);
}

async function printInfo() {
  // Get contract balance & output address + balance
  console.log('contract address:', contract.address);
  // console.log('contract balance:', (await contract.getBalance()) / 10**8);

  const utxos = await provider.getUtxos(contract.address);
  const sum = utxos.reduce((partialSum, utxo) => partialSum + utxo.satoshis / 10**8, 0);
  console.log('UTXOs:', utxos.length);
  console.log('balance:', sum);
  console.table(utxos);
}

async function sendTo(addr: string, amt: number, opRetData: string): Promise<void> {
  await printInfo();

  // Call the spend() function with alice's signature + pk
  // And use it to send BCH to addr
  let tx = contract.functions
    .spend(alicePk, new SignatureTemplate(alice))
    .to(addr, amt);
  if (opRetData.length > 0) {
    tx = tx.withOpReturn([opRetData]);
  }

  // const rawTx = await tx.build();
  // console.log('rawTx', rawTx);
  const td = await tx.send();
  console.log('transaction details:', stringify(td));
}
