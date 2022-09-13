import { BITBOX } from 'bitbox-sdk';
import { stringify } from '@bitauth/libauth';
import {
  ElectrumCluster,
  ElectrumTransport,
  ClusterOrder,
  RequestResponse,
} from 'electrum-cash';
import { 
  Contract, 
  SignatureTemplate, 
  ElectrumNetworkProvider,
} from 'cashscript';
import { compileFile } from 'cashc';
import path from 'path';

run();

async function run(): Promise<void> {
  if (process.argv.length < 4) {
    console.log('Usage: ts-node p2pkh.ts <address> <amt> [op_return_data]');
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

async function sendTo(addr: string, amt: number, opRetData: string): Promise<void> {
  // Initialise BITBOX
  const bitbox = new BITBOX();

  // Initialise HD node and alice's keypair
  const rootSeed = bitbox.Mnemonic.toSeed('smartBCH_faucet');
  const hdNode = bitbox.HDNode.fromSeed(rootSeed);
  const alice = bitbox.HDNode.toKeyPair(bitbox.HDNode.derive(hdNode, 0));

  // Derive alice's public key and public key hash
  const alicePk = bitbox.ECPair.toPublicKey(alice);
  const alicePkh = bitbox.Crypto.hash160(alicePk);

  // Compile the P2PKH contract to an artifact object
  const artifact = compileFile(path.join(__dirname, 'p2pkh.cash'));

  // Initialise a 1-of-2 Electrum Cluster with 2 hardcoded servers
  const electrum = new ElectrumCluster('CashScript Application', '1.4.1', 1, 2, ClusterOrder.PRIORITY);
  electrum.addServer('blackie.c3-soft.com', 60002, ElectrumTransport.TCP_TLS.Scheme, false);
  electrum.addServer('bch0.kister.net', 50002, ElectrumTransport.TCP_TLS.Scheme, false);

  // Initialise a network provider for network operations on TESTNET
  const provider = new ElectrumNetworkProvider('testnet', electrum);

  // Instantiate a new contract using the compiled artifact and network provider
  // AND providing the constructor parameters (pkh: alicePkh)
  const contract = new Contract(artifact, [alicePkh], provider);

  // Get contract balance & output address + balance
  console.log('contract address:', contract.address);
  console.log('contract balance:', await contract.getBalance());

  // Call the spend() function with alice's signature + pk
  // And use it to send BCH to addr
  let tx = contract.functions
    .spend(alicePk, new SignatureTemplate(alice))
    .to(addr, amt);
  if (opRetData.length > 0) {
    tx = tx.withOpReturn([opRetData]);
  }

  const td = await tx.send();
  console.log('transaction details:', stringify(td));
  // const rawTx = await tx.build();
  // console.log('rawTx', rawTx);
}
