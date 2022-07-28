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
  // https://www.blockchain.com/bch-testnet/tx/84afb6667a7094cad6283fb9303a76b26ae846ec0c3f8370433dee5f75d3b1c3
  const txid = '84afb6667a7094cad6283fb9303a76b26ae846ec0c3f8370433dee5f75d3b1c3';
  const vout = 0;
  txBuilder.addInput(txid, vout);

  // output1: BCH=>sBCH
  const ccAddr = 'bchtest:prx037ejft4me86n5lajsyu284crh8nq6qlqjscazv';
  const ccAmt = 10000;
  txBuilder.addOutput(ccAddr, ccAmt);

  // output2: change
  const myAddr = 'bchtest:qp5vev8yjxzyf0wmqhwvkvfa3jtear397gwsfxg7sa';
  const myAmt = 100000;
  // const balance = await bitbox.Address.details(myAddr)
  txBuilder.addOutput(myAddr, myAmt-ccAmt-5000);

  // output3: sBCHAddr
  const retData = Buffer.from('7342434841646472c370743331B37d3C6D0Ee798B3918f6561Af2C92', 'hex');
  const nullDataScript = bitbox.Script.nullData.output.encode(retData);
  // console.log(nullDataScript);
  txBuilder.addOutput(nullDataScript, 0);

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
  // Transaction ID: 7ff88192c5a5ee27237880230b4a9fc0c7e97d7dfe979831b23cd104d46160ee
}
