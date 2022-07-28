import { BITBOX } from 'bitbox-sdk';
import { ElectrumNetworkProvider } from 'cashscript';

run();

async function run(): Promise<void> {
  const rawTx = process.argv[2];
  console.log('rawTx:', rawTx);

  // Broadcast transation to the network
  const provider = new ElectrumNetworkProvider('testnet');
  const broadcast = await provider.sendRawTransaction(rawTx);
  console.log(`Transaction ID: ${broadcast}`);
}
