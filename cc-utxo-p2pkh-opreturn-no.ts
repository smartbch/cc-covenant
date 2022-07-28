import { BITBOX } from 'bitbox-sdk';
import { ElectrumNetworkProvider } from 'cashscript';


const network = 'testnet';

// Initialise BITBOX
const bitbox = new BITBOX({ restURL: `https://trest.bitcoin.com/v2/` });

// Initialise HD node
const rootSeed = bitbox.Mnemonic.toSeed('alice');
const hdNode = bitbox.HDNode.fromSeed(rootSeed);

const aliceNode = bitbox.HDNode.derive(hdNode, 1234);
const aliceKeyPair = bitbox.HDNode.toKeyPair(aliceNode);
const alicePubKey = bitbox.ECPair.toPublicKey(aliceKeyPair);
const alicePkh = bitbox.Crypto.hash160(alicePubKey);
const aliceCashAddr = bitbox.Address.hash160ToCash(alicePkh.toString('hex'), 0x6f);

console.log('alicePkh:', alicePkh.toString('hex'));
console.log('aliceCashAddr:', aliceCashAddr);
// aliceCashAddr: bchtest:qp5vev8yjxzyf0wmqhwvkvfa3jtear397gwsfxg7sa

run();

async function run(): Promise<void> {
  const txBuilder = new bitbox.TransactionBuilder(network);

  // input
  // https://www.blockchain.com/bch-testnet/tx/b8bdff274da6150e43f7b10bed1a2a21e2d74676ac2dc16e5ee3fee897f54c98
  const txid = 'b8bdff274da6150e43f7b10bed1a2a21e2d74676ac2dc16e5ee3fee897f54c98';
  const vout = 1;
  txBuilder.addInput(txid, vout);

  // output1: BCH=>sBCH
  const ccAddr = 'bchtest:prx037ejft4me86n5lajsyu284crh8nq6qlqjscazv';
  const ccAmt = 10000;
  txBuilder.addOutput(ccAddr, ccAmt);

  // output2: change
  const myAddr = 'bchtest:qp5vev8yjxzyf0wmqhwvkvfa3jtear397gwsfxg7sa';
  const myAmt = 100000-10000-5000-10000-5000;
  // const balance = await bitbox.Address.details(myAddr)
  txBuilder.addOutput(myAddr, myAmt-ccAmt-5000);

  // const script = new bitbox.Script();
  // const retData = Buffer.from('1234567890', 'hex');
  // const nullDataScript = bitbox.Script.nullData.output.encode(retData);
  // // console.log(nullDataScript);
  // txBuilder.addOutput(nullDataScript, 0);

  // Sign the transaction with the HD node.
  let redeemScript
  txBuilder.sign(
    0,
    aliceKeyPair,
    redeemScript,
    txBuilder.hashTypes.SIGHASH_ALL,
    myAmt
  );

  // build tx
  const tx = txBuilder.build();
  // output rawhex
  const hex = tx.toHex();
  console.log(hex);

  // Broadcast transation to the network
  const provider = new ElectrumNetworkProvider('testnet');
  const broadcast = await provider.sendRawTransaction(hex);
  console.log(`Transaction ID: ${broadcast}`);
  // Transaction ID: 3a9eb8d0a8bb046f4b0e4423a83612803c6a0c8a0731e1e5895be6ad42144781
}
