# Generating and signing TXs on cc-UTXO

> Cross-chain UTXOs (cc-UTXOs) are a special kind of covenants. The internal logic is: 1) when 7-of-10 operators agree, a UTXO can be transferred to a P2PKH address, or a new operator set; 2) if a cc-UTXO has not been moved for a long time, then the monitors can transfer it to a new operator set. The smartbchd nodes will analyze the transactions on BCH main chain to trace the cc-UTXOs' creation, redemption (transferred to a P2PKH address), and movements (to a new validator set).

## Implementation of cc-UTXO

Following cashscript implements cc-UTXO (cc-covenant) on BitcoinCash main chain:

```solidity
pragma cashscript ^0.7.2;

contract CCCovenant(bytes20 monitorPubkeysHash,
                    bytes20 operatorPubkeysHash) {

    function redeemOrConvert(
            sig sig0, sig sig1, sig sig2, sig sig3, sig sig4, sig sig5, sig sig6,
            pubkey op0, pubkey op1, pubkey op2, pubkey op3, pubkey op4,
            pubkey op5, pubkey op6, pubkey op7, pubkey op8, pubkey op9,
            bytes20 newMonitorPubkeysHash,
            bytes20 newOperatorPubkeysHash
    ) {
        require(hash160(op0+op1+op2+op3+op4+op5+op6+op7+op8+op9) == operatorPubkeysHash);
        require(checkMultiSig([sig0, sig1, sig2, sig3, sig4, sig5, sig6], 
            [op0, op1, op2, op3, op4, op5, op6, op7, op8, op9]));

        require(tx.inputs.length == 1);
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == tx.inputs[0].value - 2000); // miner fee is hardcoded

        if (newMonitorPubkeysHash != monitorPubkeysHash
                || newOperatorPubkeysHash != operatorPubkeysHash) {

            // convertByOperators
            bytes newContract = 0x14 + newOperatorPubkeysHash + 0x14 + newMonitorPubkeysHash + this.activeBytecode.split(42)[1];
            bytes23 newContractLock = new LockingBytecodeP2SH(hash160(newContract));
            require(tx.outputs[0].lockingBytecode == newContractLock);
        }
    }

    function convertByMonitors(
            sig sig0, sig sig1,
            pubkey m0, pubkey m1, pubkey m2,
            bytes20 newOperatorPubkeysHash
    ) {
        require(hash160(m0+m1+m2) == monitorPubkeysHash);
        require(checkMultiSig([sig0, sig1], [m0, m1, m2]));

        require(this.activeInputIndex == 0);
        require(tx.outputs[0].value == tx.inputs[0].value);
        require(tx.age >= 25920); // 6 * 24 * 180

        bytes newContract = 0x14 + newOperatorPubkeysHash + this.activeBytecode.split(21)[1];
        bytes23 newContractLock = new LockingBytecodeP2SH(hash160(newContract));
        require(tx.outputs[0].lockingBytecode == newContractLock);
    }

}
```

Important notes:

1. Due to [a limitation](https://github.com/gcash/bchd/blob/master/txscript/script.go#L43) of BCH script, we cannot store the pubkeys of operators and monitors in the constructor. We can only put their concatenated bytes' hash160 digest into the constructor. Whenever the UTXO is spent, the pubkeys must be attached as arguments and will be verified against the hash160 digest.

2. To further reduce the size of compiled bytecode, redeeming and coverting are implemented in one function.

The compiled redeem script has 117 opcodes:

```
$ cashc --opcount cc-covenant-mainnet.cash 
Opcode count: 117
```

The following command can generate a redeem script without constructor (172 bytes in total):

```
# Be sure to use cashc v0.7.2+
# npm install -g cashc
$ cashc -h cc-covenant-mainnet.cash

5279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768
```

The following script can generate the full redeem script with constructor (214 bytes in total) and its P2SH address (for the testnet):

```
$ cd covenants
$ ts-node cc-covenant-mainnet.ts

monitorPks: [
  '02f51c5abd464c06c0669c39e88e72060e3eed983c6ccb1201cad6e25c642a0ef9',
  '021d820f99bee3a94f26f3797af7d0589ebfc31999824cfbda935a508957ab72ac',
  '02bff2af49ecd5cd9de5fa91c431ba2067b4331dd257f480d4966c1484bc24d81e'
]
monitorPubkeysHash: 25e4c6f7423b43caa5c6ef364f5373cc66aef1c9
operatorPks: [
  '02d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd6994',
  '035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd8',
  '03fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e4',
  '038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af5',
  '0394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af1',
  '0271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c',
  '02fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873',
  '0386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d',
  '03bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca',
  '03883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f8243'
]
operatorPubkeysHash: 553fac4027a7a3c4e8a3eaea75aab173d3c8144b
redeemScriptHex: 14553fac4027a7a3c4e8a3eaea75aab173d3c8144b1425e4c6f7423b43caa5c6ef364f5373cc66aef1c95279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768
>> redeemScriptHash: d249e041382d01f22d267c2f61921e988f18de3d
>> cash addr: bchtest:prfynczp8qksru3dye7z7cvjr6vg7xx785ctvgxt3c
>> old addr: 2NCR8PZaQkAG1JngwhU9jZyinndAXdk3XcS
```

## redeem script without constructor

The bytes of the redeem script without constructor will be hard coded into the source code for smartbchd, monitors and operators.

The following code can show the assembly code (opcode sequence) of the the redeem script without constructor:

```
$ cashc -A cc-covenant-testnet.cash

OP_2 OP_PICK OP_0 OP_NUMEQUAL OP_IF OP_10 OP_PICK OP_12 OP_PICK OP_CAT OP_13 OP_PICK OP_CAT OP_14 OP_PICK OP_CAT OP_15 OP_PICK OP_CAT OP_16 OP_PICK OP_CAT 11 OP_PICK OP_CAT 12 OP_PICK OP_CAT 13 OP_PICK OP_CAT 14 OP_PICK OP_CAT OP_HASH160 OP_2 OP_PICK OP_EQUALVERIFY OP_0 OP_2ROT OP_SWAP OP_6 OP_ROLL OP_7 OP_ROLL OP_8 OP_ROLL OP_9 OP_ROLL OP_10 OP_ROLL OP_7 OP_12 OP_ROLL OP_13 OP_ROLL OP_14 OP_ROLL OP_15 OP_ROLL OP_16 OP_ROLL 11 OP_ROLL 12 OP_ROLL 13 OP_ROLL 14 OP_ROLL 15 OP_ROLL OP_10 OP_CHECKMULTISIGVERIFY OP_TXINPUTCOUNT OP_1 OP_NUMEQUALVERIFY OP_TXOUTPUTCOUNT OP_1 OP_NUMEQUALVERIFY OP_0 OP_OUTPUTVALUE OP_0 OP_UTXOVALUE d007 OP_SUB OP_NUMEQUALVERIFY OP_3 OP_PICK OP_EQUAL OP_NOT OP_4 OP_PICK OP_ROT OP_EQUAL OP_NOT OP_BOOLOR OP_IF 14 OP_3 OP_PICK OP_CAT 14 OP_CAT OP_2 OP_PICK OP_CAT OP_ACTIVEBYTECODE 2a OP_SPLIT OP_NIP OP_CAT a914 OP_OVER OP_HASH160 OP_CAT 87 OP_CAT OP_0 OP_OUTPUTBYTECODE OP_OVER OP_EQUALVERIFY OP_2DROP OP_ENDIF OP_2DROP OP_DROP OP_1 OP_ELSE OP_ROT OP_1 OP_NUMEQUALVERIFY OP_4 OP_PICK OP_6 OP_PICK OP_CAT OP_7 OP_PICK OP_CAT OP_HASH160 OP_EQUALVERIFY OP_0 OP_2SWAP OP_SWAP OP_2 OP_5 OP_ROLL OP_6 OP_ROLL OP_7 OP_ROLL OP_3 OP_CHECKMULTISIGVERIFY OP_INPUTINDEX OP_0 OP_NUMEQUALVERIFY OP_0 OP_OUTPUTVALUE OP_0 OP_UTXOVALUE OP_NUMEQUALVERIFY 4065 OP_CHECKSEQUENCEVERIFY OP_DROP 14 OP_ROT OP_CAT OP_ACTIVEBYTECODE 15 OP_SPLIT OP_NIP OP_CAT a914 OP_SWAP OP_HASH160 OP_CAT 87 OP_CAT OP_0 OP_OUTPUTBYTECODE OP_EQUAL OP_NIP OP_ENDIF
```

## redeem script with constructor

The following command can show several information of the testcase:

* The operators and monitors used in the testcase (WIP & pubkey, and the hash160 of concatenated pubkeys)
* The hex-encoded bytecode of the redeem script with constructor
* The P2SH address of the cc-UTXO, which is calculated from the hash160 of redeem script.

```
$ ts-node cc-covenant-testnet.ts

operatorWIFs: [
  'L482yD31EhZopxRD3V19QEANQaYkcUZfgNKYY2TV4RTCXa6izAKo',
  'L4JzvBMUmkQCTdz2zbVgTyW8dDMvMU8HFwe413qfnBxW3vKSw6sm',
  'L3vi8Z3HJUQw3iXcgRkbcPVku6R1XA2V6iLCG6NeuqRTvt4mUV6K',
  'L5mXQBYy1nKMTxXA3LmvUVH9pfBeaKzCKiYNszkj88s2vQEocyUs',
  'L15emxZt9yyY6ZxxRGvKRm72CMZaCRDKbSRmdRwu5h2wCUGdfwwb',
  'L5X85r9Bbf86jyf4wSRXxttPwWmkcGcv2tHhZ9eD6YiNZnZcPqZX',
  'L3HPpfMVSmYN9Y3tVJT2UorzNyWjZEQMHHuJmZKnwAGpudpA1o93',
  'L44W5cEBFAY4kcSm5q7ch8Ko3AsXV1MfJDDq1oq1u797EkhutH8s',
  'KxnPxfZ3VJtdfJm7dk1g4PeHJWz9BqRJwk6wfdNMTqeUiJJRphzD',
  'KzPnubj5tnS8efj2nApUK3wnsHCKAS6khHYxPCaciT474mNs6vfJ'
]
operatorPks: [
  '02d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd6994',
  '035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd8',
  '03fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e4',
  '038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af5',
  '0394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af1',
  '0271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c',
  '02fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873',
  '0386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d',
  '03bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca',
  '03883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f8243'
]
operatorPubkeysHash: 553fac4027a7a3c4e8a3eaea75aab173d3c8144b
monitorWIFs: [
  'L4GUc8432jgYMVxa1UhF1UC9Mxer5N7exdhbVLugZgWsR29U2pcw',
  'Kxr5EpWHx2WB5TKXRqqZVPNnEqB7zisXaRS6QgVTMGogzua9JFjP',
  'L2M9cNJ7oQeHMnBVFyDZPhGAGNB3v6swcX1xRiYUPj7Fpcjnv3UV'
]
monitorPks: [
  '024a899d685daf6b1999a5c8f2fd3c9ed640d58e92fd0e00cf87cacee8ff1504b8',
  '0374ac9ab3415253dbb7e29f46a69a3e51b5d2d66f125b0c9f2dc990b1d2e87e17',
  '024cc911ba9d2c7806a217774618b7ba4848ccd33fe664414fc3144d144cdebf7b'
]
monitorPubkeysHash: 27c4ca4766591e6bb8cd71b83143946c53eaf9a3
----------
redeemScriptHex: 14553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768
>> redeemScriptHash: 7fb25b1857fbfcea5a4a2b9941abfdf8bd430f38
>> cash addr: bchtest:pplmykcc2lale6j6fg4ejsdtlhut6sc08q7uv8pxhm
>> old addr: 2N4tRU2YaiocZeRqA4LPTxdsbVcfeBzGac7
```

From these outputs, we can see the redeem script with constructor is `14553f...877768`, and the P2SH address of it is `pplmykcc2lale6j6fg4ejsdtlhut6sc08q7uv8pxhm`.

By diassembling the bytecodes, we can see the whole redeem script with constructor has the following structure:

```
OP_PUSHNEXT20(0x14) 0x553fac4027a7a3c4e8a3eaea75aab173d3c8144b # operatorPubkeysHash
OP_PUSHNEXT20(0x14) 0x27c4ca4766591e6bb8cd71b83143946c53eaf9a3 # monitorPubkeysHash
<redeem_script_without_constructor_args>
```

## Generate Redeem Script and P2SH address in Golang

We need following steps:

1. Get the redeem script without constructor, which is hard coded in the source code

2. Get the pubkey list of operators and monitors (each entry has 33 bytes)

3. Calculate the hash160 digest of the concatenated pubkeys

4. Use this digest as constructor parameter for the redeem script

5. Calculate the P2SH address for this redeem script with constructor

You can find the corresponding Golang code [here](https://github.com/smartbch/smartbch/blob/b2fbf8979c67951925a59d387bad74f192c1f7fc/internal/ccutils/cc_covenant.go#L48). The core logic is as below:

```golang
func (c CcCovenant) BuildFullRedeemScript() ([]byte, error) {
    operatorPubkeysHash := bchutil.Hash160(bytes.Join(c.operatorPks, nil))
    monitorPubkeysHash := bchutil.Hash160(bytes.Join(c.monitorPks, nil))

    builder := txscript.NewScriptBuilder()
    builder.AddData(monitorPubkeysHash)
    builder.AddData(operatorPubkeysHash)
    builder.AddOps(c.redeemScriptWithoutConstructorArgs)

    return builder.Script()
}
```

And the code for generating P2SH address is [here](https://github.com/smartbch/smartbch/blob/b2fbf8979c67951925a59d387bad74f192c1f7fc/internal/ccutils/cc_covenant.go#L60)：

```golang
func (c CcCovenant) GetP2SHAddress() (string, error) {
    redeemScript, err := c.BuildFullRedeemScript()
    if err != nil {
        return "", err
    }

    redeemHash := bchutil.Hash160(redeemScript)
    addr, err := bchutil.NewAddressScriptHashFromHash(redeemHash, c.net)
    if err != nil {
        return "", err
    }

    return addr.EncodeAddress(), nil
}
```

Following is some [testcases](https://github.com/smartbch/smartbch/blob/b2fbf8979c67951925a59d387bad74f192c1f7fc/internal/ccutils/cc_covenant_test.go#L14)：

```golang
func Test_GetP2SHAddr(t *testing.T) {
    redeemScriptWithoutConstructorArgs := testutils.HexToBytes("5279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00c600cc02d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00c600cc9d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768")
    operatorPks := [][]byte{
        testutils.HexToBytes("02d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd6994"),
        testutils.HexToBytes("035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd8"),
        testutils.HexToBytes("03fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e4"),
        testutils.HexToBytes("038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af5"),
        testutils.HexToBytes("0394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af1"),
        testutils.HexToBytes("0271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c"),
        testutils.HexToBytes("02fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873"),
        testutils.HexToBytes("0386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d"),
        testutils.HexToBytes("03bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca"),
        testutils.HexToBytes("03883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f8243"),
    }
    monitorPks := [][]byte{
        testutils.HexToBytes("024a899d685daf6b1999a5c8f2fd3c9ed640d58e92fd0e00cf87cacee8ff1504b8"),
        testutils.HexToBytes("0374ac9ab3415253dbb7e29f46a69a3e51b5d2d66f125b0c9f2dc990b1d2e87e17"),
        testutils.HexToBytes("024cc911ba9d2c7806a217774618b7ba4848ccd33fe664414fc3144d144cdebf7b"),
    }

    c, err := NewCcCovenant(redeemScriptWithoutConstructorArgs, operatorPks, monitorPks, &chaincfg.TestNet3Params)
    require.NoError(t, err)
    addr, err := c.GetP2SHAddress()
    require.Equal(t, "pz8c39d9nse9a2jkretut3z96t7ymtnyag8rkkunun", addr)
}
```

## Create cc-UTXO by transfering test coins

```
$ ts-node p2pkh.ts bchtest:pplmykcc2lale6j6fg4ejsdtlhut6sc08q7uv8pxhm 10000

{
  "inputs": [
    {
      "outpointIndex": 1,
      "outpointTransactionHash": "<Uint8Array: 0xea65c4214957eb786d3b1d01891414600691c88de6584b9e8ebad7347485c978>",
      "sequenceNumber": 4294967294,
      "unlockingBytecode": "<Uint8Array: 0x413199f33a7f2fc1f4f9b6075abdaea8c8f3cf7d3453581d5a0bcdb39b3d0380006bf31d6915b16ebdd0ecae3e71bfe51ffdb1279c71932d80c26f7d59ee722ca041210380690473f0f8dcd6f3196e044d4fc160c44597315ccd6a42117f1d6f56cc960819143ed2b14d2418fdf1b384abbf9bbe4a9b9524ca6178a988ac>"
    }
  ],
  "locktime": 1511441,
  "outputs": [
    {
      "lockingBytecode": "<Uint8Array: 0xa9147fb25b1857fbfcea5a4a2b9941abfdf8bd430f3887>",
      "satoshis": "<Uint8Array: 0x1027000000000000>"
    },
    {
      "lockingBytecode": "<Uint8Array: 0xa91483eb112ad5945d4463cd4a8cd4881fcad8478c7e87>",
      "satoshis": "<Uint8Array: 0x71691f0400000000>"
    }
  ],
  "version": 2,
  "txid": "4794c49d6cc88d87a0b73f0a35e87f7892cdfeec416724890ce10176aecd027c",
  "hex": "020000000178c9857434d7ba8e9e4b58e68dc8910660141489011d3b6d78eb574921c465ea010000007e413199f33a7f2fc1f4f9b6075abdaea8c8f3cf7d3453581d5a0bcdb39b3d0380006bf31d6915b16ebdd0ecae3e71bfe51ffdb1279c71932d80c26f7d59ee722ca041210380690473f0f8dcd6f3196e044d4fc160c44597315ccd6a42117f1d6f56cc960819143ed2b14d2418fdf1b384abbf9bbe4a9b9524ca6178a988acfeffffff02102700000000000017a9147fb25b1857fbfcea5a4a2b9941abfdf8bd430f388771691f040000000017a91483eb112ad5945d4463cd4a8cd4881fcad8478c7e8711101700"
}
```

## Redeem ccUTXO using CashScriptSDK

Given a cc-UTXO (txid and vout) and a target account (toAddr), we need the following steps to redeem it, according to the [specification](https://www.reference.cash/protocol/blockchain/transaction/transaction-signing):

1. Using these information to construct a unsigned tx

2. Calculate its txSigHash

3. Let operators sign this txSigHash

4. Construct a full unlocking script (also known as sigScript)

5. Complete the unsigned tx with this unlocking script to get a signed tx, which is serialed in hex format

6. broadcast this hex string

It is easy to do these steps in CashScriptSDK:

```javascript
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
      monitorPubkeysHash,
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
```

Following is a tx for testing, on the testnet:

```javascript
contract UTXOs  : [
  {
    txid: '4794c49d6cc88d87a0b73f0a35e87f7892cdfeec416724890ce10176aecd027c',
    vout: 0,
    satoshis: 10000,
    height: 1511442
  }
]
transaction details: {
  "inputs": [
    {
      "outpointIndex": 0,
      "outpointTransactionHash": "<Uint8Array: 0x4794c49d6cc88d87a0b73f0a35e87f7892cdfeec416724890ce10176aecd027c>",
      "sequenceNumber": 4294967294,
      "unlockingBytecode": "<Uint8Array: 0x14553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a32103883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f82432103bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca210386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d2102fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873210271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c210394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af121038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af52103fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e421035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd82102d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd699447304402207bd5dd3fce07a56d28a1e456c538901fbc9820f52855f5502ecb7c5a35b05d41022027611a420ba0617764672d11bf908c7f31b6f05f66ca2268fa3135f689515214414730440220148300596475fd0b80c2e9704caa4a77485ab50e6666b80dec73d067ed38a30402205385a562dde1c06e15d33280b32908ce2ca42f6ef9760feb646679fafe1aeaae4147304402205b5d26db1d7cd4b9ddebef0c3a74124d5b8ce549946d2ddcd6ba9121d8adb886022038d0572915960a1e1ca4e921c4bf6432e336f83e2c2a5f7e48697783d8ef92fd414730440220541a6035542abd33b318584b01a62ea4678e4d407e28ec5c4a1d98be8da20a7802203e05ae652cb0a8f615fca5a0531df7111da80a7985598f446761ccf7ccbea8b241483045022100a2e36c1b73bfe1baa2eb4a44c5ee675eaee67e85a26eecf5d54cbddf655ba3e802207fb19769f4e9ba97093af84a1bc96465c76c9a4d10b23d76d84049d6e9517c91414730440220081a832b6f0beef5a2311bc24eb818bb34e598d88fa9cc217b41e4d88cc517de02203f158e5746f481a4676c3cbe7edd6a2e648a2294552458d64fea0dda27ad72ed4147304402203b289d27eed12a2abb874c41a36bee14c5a4340f34e1306c21b32fad2040613b022061db8baa44af6adffc0f420bd7ff40b23501fb0d3a32e86e718730e2729d965841004cf914553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768>"
    }
  ],
  "locktime": 1511442,
  "outputs": [
    {
      "lockingBytecode": "<Uint8Array: 0x76a91499c7e0b48a05cd6024b22cd490fcee30aa51d86288ac>",
      "satoshis": "<Uint8Array: 0x401f000000000000>"
    }
  ],
  "version": 2,
  "txid": "bd1731ce1a008e0b778fe73f20b67e49df2acd178ff81b09bd8a91b8acdd9538",
  "hex": "02000000017c02cdae7601e10c89246741ecfecd92787fe8350a3fb7a0878dc86c9dc4944700000000fd730414553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a32103883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f82432103bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca210386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d2102fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873210271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c210394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af121038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af52103fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e421035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd82102d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd699447304402207bd5dd3fce07a56d28a1e456c538901fbc9820f52855f5502ecb7c5a35b05d41022027611a420ba0617764672d11bf908c7f31b6f05f66ca2268fa3135f689515214414730440220148300596475fd0b80c2e9704caa4a77485ab50e6666b80dec73d067ed38a30402205385a562dde1c06e15d33280b32908ce2ca42f6ef9760feb646679fafe1aeaae4147304402205b5d26db1d7cd4b9ddebef0c3a74124d5b8ce549946d2ddcd6ba9121d8adb886022038d0572915960a1e1ca4e921c4bf6432e336f83e2c2a5f7e48697783d8ef92fd414730440220541a6035542abd33b318584b01a62ea4678e4d407e28ec5c4a1d98be8da20a7802203e05ae652cb0a8f615fca5a0531df7111da80a7985598f446761ccf7ccbea8b241483045022100a2e36c1b73bfe1baa2eb4a44c5ee675eaee67e85a26eecf5d54cbddf655ba3e802207fb19769f4e9ba97093af84a1bc96465c76c9a4d10b23d76d84049d6e9517c91414730440220081a832b6f0beef5a2311bc24eb818bb34e598d88fa9cc217b41e4d88cc517de02203f158e5746f481a4676c3cbe7edd6a2e648a2294552458d64fea0dda27ad72ed4147304402203b289d27eed12a2abb874c41a36bee14c5a4340f34e1306c21b32fad2040613b022061db8baa44af6adffc0f420bd7ff40b23501fb0d3a32e86e718730e2729d965841004cf914553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768feffffff01401f0000000000001976a91499c7e0b48a05cd6024b22cd490fcee30aa51d86288ac12101700"
}
```

In the following sections, we will analyze the unlocking script:

```
0x14553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a32103883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f82432103bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca210386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d2102fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873210271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c210394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af121038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af52103fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e421035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd82102d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd699447304402207bd5dd3fce07a56d28a1e456c538901fbc9820f52855f5502ecb7c5a35b05d41022027611a420ba0617764672d11bf908c7f31b6f05f66ca2268fa3135f689515214414730440220148300596475fd0b80c2e9704caa4a77485ab50e6666b80dec73d067ed38a30402205385a562dde1c06e15d33280b32908ce2ca42f6ef9760feb646679fafe1aeaae4147304402205b5d26db1d7cd4b9ddebef0c3a74124d5b8ce549946d2ddcd6ba9121d8adb886022038d0572915960a1e1ca4e921c4bf6432e336f83e2c2a5f7e48697783d8ef92fd414730440220541a6035542abd33b318584b01a62ea4678e4d407e28ec5c4a1d98be8da20a7802203e05ae652cb0a8f615fca5a0531df7111da80a7985598f446761ccf7ccbea8b241483045022100a2e36c1b73bfe1baa2eb4a44c5ee675eaee67e85a26eecf5d54cbddf655ba3e802207fb19769f4e9ba97093af84a1bc96465c76c9a4d10b23d76d84049d6e9517c91414730440220081a832b6f0beef5a2311bc24eb818bb34e598d88fa9cc217b41e4d88cc517de02203f158e5746f481a4676c3cbe7edd6a2e648a2294552458d64fea0dda27ad72ed4147304402203b289d27eed12a2abb874c41a36bee14c5a4340f34e1306c21b32fad2040613b022061db8baa44af6adffc0f420bd7ff40b23501fb0d3a32e86e718730e2729d965841004cf914553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768
```

## The unlocking script for redeeming ccUTXO

Diassemble the above unlocking script, we can get its OPCODE sequence:

```
OP_PUSHNEXT20(0x14) 0x553fac4027a7a3c4e8a3eaea75aab173d3c8144b
OP_PUSHNEXT20(0x14) 0x27c4ca4766591e6bb8cd71b83143946c53eaf9a3
OP_PUSHNEXT33(0x21) 0x03883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f8243
OP_PUSHNEXT33(0x21) 0x03bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca
OP_PUSHNEXT33(0x21) 0x0386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d
OP_PUSHNEXT33(0x21) 0x02fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873
OP_PUSHNEXT33(0x21) 0x0271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c
OP_PUSHNEXT33(0x21) 0x0394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af1
OP_PUSHNEXT33(0x21) 0x038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af5
OP_PUSHNEXT33(0x21) 0x03fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e4
OP_PUSHNEXT33(0x21) 0x035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd8
OP_PUSHNEXT33(0x21) 0x02d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd6994
OP_PUSHNEXT71(0x47) 0x304402207bd5dd3fce07a56d28a1e456c538901fbc9820f52855f5502ecb7c5a35b05d41022027611a420ba0617764672d11bf908c7f31b6f05f66ca2268fa3135f68951521441
OP_PUSHNEXT71(0x47) 0x30440220148300596475fd0b80c2e9704caa4a77485ab50e6666b80dec73d067ed38a30402205385a562dde1c06e15d33280b32908ce2ca42f6ef9760feb646679fafe1aeaae41
OP_PUSHNEXT71(0x47) 0x304402205b5d26db1d7cd4b9ddebef0c3a74124d5b8ce549946d2ddcd6ba9121d8adb886022038d0572915960a1e1ca4e921c4bf6432e336f83e2c2a5f7e48697783d8ef92fd41
OP_PUSHNEXT71(0x47) 0x30440220541a6035542abd33b318584b01a62ea4678e4d407e28ec5c4a1d98be8da20a7802203e05ae652cb0a8f615fca5a0531df7111da80a7985598f446761ccf7ccbea8b241
OP_PUSHNEXT72(0x48) 0x3045022100a2e36c1b73bfe1baa2eb4a44c5ee675eaee67e85a26eecf5d54cbddf655ba3e802207fb19769f4e9ba97093af84a1bc96465c76c9a4d10b23d76d84049d6e9517c9141
OP_PUSHNEXT71(0x47) 0x30440220081a832b6f0beef5a2311bc24eb818bb34e598d88fa9cc217b41e4d88cc517de02203f158e5746f481a4676c3cbe7edd6a2e648a2294552458d64fea0dda27ad72ed41
OP_PUSHNEXT71(0x47) 0x304402203b289d27eed12a2abb874c41a36bee14c5a4340f34e1306c21b32fad2040613b022061db8baa44af6adffc0f420bd7ff40b23501fb0d3a32e86e718730e2729d965841
OP_0(0x00)
OP_PUSHDATA1(0x4c) 0xf9 0x14553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768
```

The first 19 instructions push the 19 argmuments of redeemOrConvert to the stack. Please note the pushing order is reverse to the order in source code. The 20th instruction pushes the function selector (0 for the first function). The 21st instruction pushes the redeem script's bytecode to stack.

If we replace the data in the code with readable symbols, and include the locking script (also known as pubkeyScript), it would be much easier to see the whole graph:

```
# unlocking script
push <newOperatorPubkeysHash>
push <newMonitorPubkeysHash>
push <op9>
push <op8>
push <op7>
push <op6>
push <op5>
push <op4>
push <op3>
push <op2>
push <op1>
push <op0>
push <sig6>
push <sig5>
push <sig4>
push <sig3>
push <sig2>
push <sig1>
push <sig0>
push 0
push <redeem_script_prefixed_with_constructor_args>
# locking script
OP_HASH160
0x7fb25b1857fbfcea5a4a2b9941abfdf8bd430f38
OP_EQUAL
```

The golang code to generate the unlockingScript for redeeming is [here](https://github.com/smartbch/smartbch/blob/2d957f23368f1bdd347edd422545764f29368560/internal/ccutils/cc_covenant.go#L165)：

```go
func (c *CcCovenant) BuildRedeemByUserUnlockingScript(sigs [][]byte) ([]byte, error) {
    return c.BuildRedeemOrConvertUnlockingScript(sigs, c.operatorPks, c.monitorPks)
}

func (c *CcCovenant) BuildRedeemOrConvertUnlockingScript(sigs [][]byte,
    newOperatorPks [][]byte,
    newMonitorPks [][]byte,
) ([]byte, error) {

    if len(sigs) != operatorSigCount {
        return nil, errors.New("invalid operator signature count")
    }
    err := checkPks(newOperatorPks, newMonitorPks)
    if err != nil {
        return nil, err
    }

    redeemScript, err := c.BuildFullRedeemScript()
    if err != nil {
        return nil, err
    }

    builder := txscript.NewScriptBuilder()
    builder.AddData(bchutil.Hash160(bytes.Join(newOperatorPks, nil)))
    builder.AddData(bchutil.Hash160(bytes.Join(newMonitorPks, nil)))
    for i := len(c.operatorPks) - 1; i >= 0; i-- {
        builder.AddData(c.operatorPks[i])
    }
    for i := len(sigs) - 1; i >= 0; i-- {
        builder.AddData(sigs[i])
    }
    builder.AddInt64(0) // selector
    builder.AddData(redeemScript)
    return builder.Script()
}
```

The testcase:

```golang
func Test_BuildRedeemByUserUnlockingScript(t *testing.T) {
    redeemScriptWithoutConstructorArgs := testutils.HexToBytes("5279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768")
    operatorPks := [][]byte{
        testutils.HexToBytes("02d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd6994"),
        testutils.HexToBytes("035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd8"),
        testutils.HexToBytes("03fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e4"),
        testutils.HexToBytes("038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af5"),
        testutils.HexToBytes("0394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af1"),
        testutils.HexToBytes("0271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c"),
        testutils.HexToBytes("02fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873"),
        testutils.HexToBytes("0386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d"),
        testutils.HexToBytes("03bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca"),
        testutils.HexToBytes("03883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f8243"),
    }
    monitorPks := [][]byte{
        testutils.HexToBytes("024a899d685daf6b1999a5c8f2fd3c9ed640d58e92fd0e00cf87cacee8ff1504b8"),
        testutils.HexToBytes("0374ac9ab3415253dbb7e29f46a69a3e51b5d2d66f125b0c9f2dc990b1d2e87e17"),
        testutils.HexToBytes("024cc911ba9d2c7806a217774618b7ba4848ccd33fe664414fc3144d144cdebf7b"),
    }

    c, err := NewCcCovenant(redeemScriptWithoutConstructorArgs, operatorPks, monitorPks, 2000, &chaincfg.TestNet3Params)
    require.NoError(t, err)

    sigScript, err := c.BuildRedeemByUserUnlockingScript([][]byte{
        testutils.HexToBytes("0x304402203b289d27eed12a2abb874c41a36bee14c5a4340f34e1306c21b32fad2040613b022061db8baa44af6adffc0f420bd7ff40b23501fb0d3a32e86e718730e2729d965841"),
        testutils.HexToBytes("0x30440220081a832b6f0beef5a2311bc24eb818bb34e598d88fa9cc217b41e4d88cc517de02203f158e5746f481a4676c3cbe7edd6a2e648a2294552458d64fea0dda27ad72ed41"),
        testutils.HexToBytes("0x3045022100a2e36c1b73bfe1baa2eb4a44c5ee675eaee67e85a26eecf5d54cbddf655ba3e802207fb19769f4e9ba97093af84a1bc96465c76c9a4d10b23d76d84049d6e9517c9141"),
        testutils.HexToBytes("0x30440220541a6035542abd33b318584b01a62ea4678e4d407e28ec5c4a1d98be8da20a7802203e05ae652cb0a8f615fca5a0531df7111da80a7985598f446761ccf7ccbea8b241"),
        testutils.HexToBytes("0x304402205b5d26db1d7cd4b9ddebef0c3a74124d5b8ce549946d2ddcd6ba9121d8adb886022038d0572915960a1e1ca4e921c4bf6432e336f83e2c2a5f7e48697783d8ef92fd41"),
        testutils.HexToBytes("0x30440220148300596475fd0b80c2e9704caa4a77485ab50e6666b80dec73d067ed38a30402205385a562dde1c06e15d33280b32908ce2ca42f6ef9760feb646679fafe1aeaae41"),
        testutils.HexToBytes("0x304402207bd5dd3fce07a56d28a1e456c538901fbc9820f52855f5502ecb7c5a35b05d41022027611a420ba0617764672d11bf908c7f31b6f05f66ca2268fa3135f68951521441"),
    })
    require.NoError(t, err)
    require.Equal(t, testutils.HexToBytes("0x14553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a32103883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f82432103bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca210386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d2102fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873210271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c210394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af121038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af52103fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e421035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd82102d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd699447304402207bd5dd3fce07a56d28a1e456c538901fbc9820f52855f5502ecb7c5a35b05d41022027611a420ba0617764672d11bf908c7f31b6f05f66ca2268fa3135f689515214414730440220148300596475fd0b80c2e9704caa4a77485ab50e6666b80dec73d067ed38a30402205385a562dde1c06e15d33280b32908ce2ca42f6ef9760feb646679fafe1aeaae4147304402205b5d26db1d7cd4b9ddebef0c3a74124d5b8ce549946d2ddcd6ba9121d8adb886022038d0572915960a1e1ca4e921c4bf6432e336f83e2c2a5f7e48697783d8ef92fd414730440220541a6035542abd33b318584b01a62ea4678e4d407e28ec5c4a1d98be8da20a7802203e05ae652cb0a8f615fca5a0531df7111da80a7985598f446761ccf7ccbea8b241483045022100a2e36c1b73bfe1baa2eb4a44c5ee675eaee67e85a26eecf5d54cbddf655ba3e802207fb19769f4e9ba97093af84a1bc96465c76c9a4d10b23d76d84049d6e9517c91414730440220081a832b6f0beef5a2311bc24eb818bb34e598d88fa9cc217b41e4d88cc517de02203f158e5746f481a4676c3cbe7edd6a2e648a2294552458d64fea0dda27ad72ed4147304402203b289d27eed12a2abb874c41a36bee14c5a4340f34e1306c21b32fad2040613b022061db8baa44af6adffc0f420bd7ff40b23501fb0d3a32e86e718730e2729d965841004cf914553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768"),
        sigScript)
}
```

## The complete flow for redeeming ccUTXO

We need the following steps:

1. assemble the unsigned tx

2. get its sigHash

3. let operators sign sigHash

4. complete the tx with sigHash and get signed tx

5. broad the signed tx

The following [code](https://github.com/smartbch/smartbch/blob/2d957f23368f1bdd347edd422545764f29368560/internal/ccutils/cc_covenant.go#L113) assembles a tx for redeeming:

```golang
func (c CcCovenant) BuildRedeemByUserUnsignedTx(
    txid string, vout uint32, inAmt int64, // input info
    toAddr string, // output info
) (*wire.MsgTx, error) {

    builder := newMsgTxBuilder(c.net)
    if err := builder.addInput(txid, vout); err != nil {
        return nil, err
    }
    if err := builder.addOutput(toAddr, inAmt-c.minerFee); err != nil {
        return nil, err
    }

    return builder.msgTx, nil
}
```

The following [code](https://github.com/smartbch/smartbch/blob/2d957f23368f1bdd347edd422545764f29368560/internal/ccutils/cc_covenant.go#L129) calculates sigHash:

```golang
func (c CcCovenant) GetRedeemByUserTxSigHash(
    txid string, vout uint32, inAmt int64, toAddr string) (*wire.MsgTx, []byte, error) {

    redeemScript, err := c.BuildFullRedeemScript()
    if err != nil {
        return nil, nil, err
    }

    tx, err := c.BuildRedeemByUserUnsignedTx(txid, vout, inAmt, toAddr)
    if err != nil {
        return nil, nil, err
    }

    sigHashes := txscript.NewTxSigHashes(tx)
    hashType := txscript.SigHashAll | txscript.SigHashForkID
    inputIdx := 0
    hash, err := txscript.CalcSignatureHash(redeemScript, sigHashes, hashType, tx, inputIdx, inAmt, true)
    return tx, hash, err
}
```

The following [code](https://github.com/smartbch/smartbch/blob/2d957f23368f1bdd347edd422545764f29368560/internal/ccutils/cc_covenant.go#L391) demonstrates the signing step:

```golang
func SignCcCovenantTxSigHashECDSA(wifStr string, hash []byte, hashType txscript.SigHashType) ([]byte, error) {
    wif, err := bchutil.DecodeWIF(wifStr)
    if err != nil {
        return nil, err
    }

    signature, err := wif.PrivKey.SignECDSA(hash)
    if err != nil {
        return nil, fmt.Errorf("cannot sign tx input: %s", err)
    }

    return append(signature.Serialize(), byte(hashType)), nil
}
```

The following [code](https://github.com/smartbch/smartbch/blob/2d957f23368f1bdd347edd422545764f29368560/internal/ccutils/cc_covenant.go#L149) completes the tx

```golang
func (c CcCovenant) FinishRedeemByUserTx(unsignedTx *wire.MsgTx, sigs [][]byte) (string, error) {
    sigScript, err := c.BuildRedeemByUserUnlockingScript(sigs)
    if err != nil {
        return "", err
    }

    inputIdx := 0
    unsignedTx.TxIn[inputIdx].SignatureScript = sigScript

    var signedTx bytes.Buffer
    _ = unsignedTx.Serialize(&signedTx)

    hexSignedTx := hex.EncodeToString(signedTx.Bytes())
    return hexSignedTx, nil
}
```

Now prepare another UTXO:

```
$ ts-node p2pkh.ts bchtest:pplmykcc2lale6j6fg4ejsdtlhut6sc08q7uv8pxhm 10000

{
  "inputs": [
    {
      "outpointIndex": 1,
      "outpointTransactionHash": "<Uint8Array: 0x4794c49d6cc88d87a0b73f0a35e87f7892cdfeec416724890ce10176aecd027c>",
      "sequenceNumber": 4294967294,
      "unlockingBytecode": "<Uint8Array: 0x4156c0efffb1207ce0b0d78f8b5f01f447c59dea7dcbeccd1430fa67717daa6945ccae8ba00b533d56297f1b25c5feda7d1334912d2aa9fd8195471f7f3989cdf341210380690473f0f8dcd6f3196e044d4fc160c44597315ccd6a42117f1d6f56cc960819143ed2b14d2418fdf1b384abbf9bbe4a9b9524ca6178a988ac>"
    }
  ],
  "locktime": 1511448,
  "outputs": [
    {
      "lockingBytecode": "<Uint8Array: 0xa9147fb25b1857fbfcea5a4a2b9941abfdf8bd430f3887>",
      "satoshis": "<Uint8Array: 0x1027000000000000>"
    },
    {
      "lockingBytecode": "<Uint8Array: 0xa91483eb112ad5945d4463cd4a8cd4881fcad8478c7e87>",
      "satoshis": "<Uint8Array: 0x6e411f0400000000>"
    }
  ],
  "version": 2,
  "txid": "c70ae4cd69afad7ac025c719055e2eefe18e3942259c2882d7afb0c39ae339ef",
  "hex": "02000000017c02cdae7601e10c89246741ecfecd92787fe8350a3fb7a0878dc86c9dc49447010000007e4156c0efffb1207ce0b0d78f8b5f01f447c59dea7dcbeccd1430fa67717daa6945ccae8ba00b533d56297f1b25c5feda7d1334912d2aa9fd8195471f7f3989cdf341210380690473f0f8dcd6f3196e044d4fc160c44597315ccd6a42117f1d6f56cc960819143ed2b14d2418fdf1b384abbf9bbe4a9b9524ca6178a988acfeffffff02102700000000000017a9147fb25b1857fbfcea5a4a2b9941abfdf8bd430f38876e411f040000000017a91483eb112ad5945d4463cd4a8cd4881fcad8478c7e8718101700"
}
```

Put them [all together](https://github.com/smartbch/smartbch/blob/b2fbf8979c67951925a59d387bad74f192c1f7fc/internal/ccutils/cc_covenant_test.go#L60)：

```golang
func Test_UserRedeemTx(t *testing.T) {
    redeemScriptWithoutConstructorArgs := testutils.HexToBytes("5279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768")
    operatorPks := [][]byte{
        testutils.HexToBytes("02d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd6994"),
        testutils.HexToBytes("035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd8"),
        testutils.HexToBytes("03fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e4"),
        testutils.HexToBytes("038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af5"),
        testutils.HexToBytes("0394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af1"),
        testutils.HexToBytes("0271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c"),
        testutils.HexToBytes("02fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873"),
        testutils.HexToBytes("0386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d"),
        testutils.HexToBytes("03bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca"),
        testutils.HexToBytes("03883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f8243"),
    }
    monitorPks := [][]byte{
        testutils.HexToBytes("024a899d685daf6b1999a5c8f2fd3c9ed640d58e92fd0e00cf87cacee8ff1504b8"),
        testutils.HexToBytes("0374ac9ab3415253dbb7e29f46a69a3e51b5d2d66f125b0c9f2dc990b1d2e87e17"),
        testutils.HexToBytes("024cc911ba9d2c7806a217774618b7ba4848ccd33fe664414fc3144d144cdebf7b"),
    }

    c, err := NewCcCovenant(redeemScriptWithoutConstructorArgs, operatorPks, monitorPks, 2000, &chaincfg.TestNet3Params)
    require.NoError(t, err)

    txid := "c70ae4cd69afad7ac025c719055e2eefe18e3942259c2882d7afb0c39ae339ef"
    vout := uint32(0)
    inAmt := int64(10000)
    toAddr := "bchtest:qzvu0c953gzu6cpykgkdfy8uacc255wcvgmp7ekj7y"
    //outAmt := int64(8000) // gasFee = 2000

    unsignedTx, sigHash, err := c.GetRedeemByUserTxSigHash(txid, vout, inAmt, toAddr)
    require.NoError(t, err)

    operatorWIFs := []string{
        "L482yD31EhZopxRD3V19QEANQaYkcUZfgNKYY2TV4RTCXa6izAKo",
        "L4JzvBMUmkQCTdz2zbVgTyW8dDMvMU8HFwe413qfnBxW3vKSw6sm",
        "L3vi8Z3HJUQw3iXcgRkbcPVku6R1XA2V6iLCG6NeuqRTvt4mUV6K",
        "L5mXQBYy1nKMTxXA3LmvUVH9pfBeaKzCKiYNszkj88s2vQEocyUs",
        "L15emxZt9yyY6ZxxRGvKRm72CMZaCRDKbSRmdRwu5h2wCUGdfwwb",
        "L5X85r9Bbf86jyf4wSRXxttPwWmkcGcv2tHhZ9eD6YiNZnZcPqZX",
        "L3HPpfMVSmYN9Y3tVJT2UorzNyWjZEQMHHuJmZKnwAGpudpA1o93",
        "L44W5cEBFAY4kcSm5q7ch8Ko3AsXV1MfJDDq1oq1u797EkhutH8s",
        "KxnPxfZ3VJtdfJm7dk1g4PeHJWz9BqRJwk6wfdNMTqeUiJJRphzD",
        "KzPnubj5tnS8efj2nApUK3wnsHCKAS6khHYxPCaciT474mNs6vfJ",
    }

    var sigs [][]byte
    hashType := txscript.SigHashAll | txscript.SigHashForkID
    for i := 0; i < 7; i++ {
        sig, err := SignCcCovenantTxSigHashECDSA(operatorWIFs[i], sigHash, hashType)
        require.NoError(t, err, i)
        sigs = append(sigs, sig)
    }

    //pkh := testutils.HexToBytes("99c7e0b48a05cd6024b22cd490fcee30aa51d862")
    rawTx, err := c.FinishRedeemByUserTx(unsignedTx, sigs)
    require.NoError(t, err)
    //println("rawTx:", rawTx)

    expectedTxHex := "0200000001ef39e39ac3b0afd782289c2542398ee1ef2e5e0519c725c07aadaf69cde40ac700000000fd730414553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a32103883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f82432103bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca210386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d2102fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873210271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c210394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af121038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af52103fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e421035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd82102d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd6994473044022031427dd1f45b9da87a7debd1b87ed4ecded757229fe4303d53622218f6ad03bc0220620d22921ebc048ce3b059a90fbd6b73bb4317eac8381fda0536122ca6d551e041473044022036b4e61517de41dff076c8ee34086144b3e0dd6643630fc3346b5c3cbe70b188022035eb4b9416cc6f57866223c09d7b7fa689107b9f8e602a50e72b10e854c58f8841473044022061f3679773b8614476ed86fcb9bd6e2e8583fa7d31f40ea8253828e8ec557494022062464d5b18009799ad2da29eb3434e39a337b92da8782110c4eff88cb189cc0a4147304402207dda8c8c17b45d59f9db2dd2c9100e199055efb9d0ae9d8288b89343e40f07320220049f93711440f3430758296e5557db9a1f6f8cdb18ecd86994ed42da932fd00c41483045022100e33a551d632b8d011160adad33cbe9313398f4eda81a4638f5b882e24df3b3ab02201499477ce35e4fe2dbb068308cf74990cbb51fa6ed923cf2f68dac5e010744c74147304402200dbc8ad06836f0a24d60da54fb2afb8db854864e5ca1bb4d982fde792500c6330220720d6f7246c23e5edf4770fbbb0e5c3680e72204be28ce2491ee9442fb62b0724147304402206f858c771e95ca1e4fac2e5580ca5b989a2ac447741154189fb99f044839eee0022049aa497292adadb2ffbdbb10a2d997f1210a0e4aa1acd354551e972db2fed00841004cf914553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768ffffffff01401f0000000000001976a91499c7e0b48a05cd6024b22cd490fcee30aa51d86288ac00000000"
    require.Equal(t, expectedTxHex, rawTx)
}
```

And broadcast it：

```
$ ts-node send-raw-tx.ts 0200000001ef39e39ac3b0afd782289c2542398ee1ef2e5e0519c725c07aadaf69cde40ac700000000fd730414553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a32103883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f82432103bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca210386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d2102fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873210271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c210394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af121038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af52103fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e421035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd82102d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd6994473044022031427dd1f45b9da87a7debd1b87ed4ecded757229fe4303d53622218f6ad03bc0220620d22921ebc048ce3b059a90fbd6b73bb4317eac8381fda0536122ca6d551e041473044022036b4e61517de41dff076c8ee34086144b3e0dd6643630fc3346b5c3cbe70b188022035eb4b9416cc6f57866223c09d7b7fa689107b9f8e602a50e72b10e854c58f8841473044022061f3679773b8614476ed86fcb9bd6e2e8583fa7d31f40ea8253828e8ec557494022062464d5b18009799ad2da29eb3434e39a337b92da8782110c4eff88cb189cc0a4147304402207dda8c8c17b45d59f9db2dd2c9100e199055efb9d0ae9d8288b89343e40f07320220049f93711440f3430758296e5557db9a1f6f8cdb18ecd86994ed42da932fd00c41483045022100e33a551d632b8d011160adad33cbe9313398f4eda81a4638f5b882e24df3b3ab02201499477ce35e4fe2dbb068308cf74990cbb51fa6ed923cf2f68dac5e010744c74147304402200dbc8ad06836f0a24d60da54fb2afb8db854864e5ca1bb4d982fde792500c6330220720d6f7246c23e5edf4770fbbb0e5c3680e72204be28ce2491ee9442fb62b0724147304402206f858c771e95ca1e4fac2e5580ca5b989a2ac447741154189fb99f044839eee0022049aa497292adadb2ffbdbb10a2d997f1210a0e4aa1acd354551e972db2fed00841004cf914553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768ffffffff01401f0000000000001976a91499c7e0b48a05cd6024b22cd490fcee30aa51d86288ac00000000

Transaction ID: 41aa421039ae5bd7b5cbb844d062a9b04cf9664ff2869c05e481f402be031306
```

The [details](https://www.blockchain.com/bch-testnet/tx/41aa421039ae5bd7b5cbb844d062a9b04cf9664ff2869c05e481f402be031306) of the tx:

```json
{
  "inputs": [
    {
      "outpointIndex": 0,
      "outpointTransactionHash": "<Uint8Array: 0xc70ae4cd69afad7ac025c719055e2eefe18e3942259c2882d7afb0c39ae339ef>",
      "sequenceNumber": 4294967295,
      "unlockingBytecode": "<Uint8Array: 0x14553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a32103883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f82432103bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca210386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d2102fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873210271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c210394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af121038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af52103fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e421035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd82102d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd6994473044022031427dd1f45b9da87a7debd1b87ed4ecded757229fe4303d53622218f6ad03bc0220620d22921ebc048ce3b059a90fbd6b73bb4317eac8381fda0536122ca6d551e041473044022036b4e61517de41dff076c8ee34086144b3e0dd6643630fc3346b5c3cbe70b188022035eb4b9416cc6f57866223c09d7b7fa689107b9f8e602a50e72b10e854c58f8841473044022061f3679773b8614476ed86fcb9bd6e2e8583fa7d31f40ea8253828e8ec557494022062464d5b18009799ad2da29eb3434e39a337b92da8782110c4eff88cb189cc0a4147304402207dda8c8c17b45d59f9db2dd2c9100e199055efb9d0ae9d8288b89343e40f07320220049f93711440f3430758296e5557db9a1f6f8cdb18ecd86994ed42da932fd00c41483045022100e33a551d632b8d011160adad33cbe9313398f4eda81a4638f5b882e24df3b3ab02201499477ce35e4fe2dbb068308cf74990cbb51fa6ed923cf2f68dac5e010744c74147304402200dbc8ad06836f0a24d60da54fb2afb8db854864e5ca1bb4d982fde792500c6330220720d6f7246c23e5edf4770fbbb0e5c3680e72204be28ce2491ee9442fb62b0724147304402206f858c771e95ca1e4fac2e5580ca5b989a2ac447741154189fb99f044839eee0022049aa497292adadb2ffbdbb10a2d997f1210a0e4aa1acd354551e972db2fed00841004cf914553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768>"
    }
  ],
  "locktime": 0,
  "outputs": [
    {
      "lockingBytecode": "<Uint8Array: 0x76a91499c7e0b48a05cd6024b22cd490fcee30aa51d86288ac>",
      "satoshis": "<Uint8Array: 0x401f000000000000>"
    }
  ],
  "version": 2,
  "txid": "41aa421039ae5bd7b5cbb844d062a9b04cf9664ff2869c05e481f402be031306",
  "hex": "0200000001ef39e39ac3b0afd782289c2542398ee1ef2e5e0519c725c07aadaf69cde40ac700000000fd730414553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a32103883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f82432103bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca210386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d2102fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873210271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c210394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af121038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af52103fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e421035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd82102d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd6994473044022031427dd1f45b9da87a7debd1b87ed4ecded757229fe4303d53622218f6ad03bc0220620d22921ebc048ce3b059a90fbd6b73bb4317eac8381fda0536122ca6d551e041473044022036b4e61517de41dff076c8ee34086144b3e0dd6643630fc3346b5c3cbe70b188022035eb4b9416cc6f57866223c09d7b7fa689107b9f8e602a50e72b10e854c58f8841473044022061f3679773b8614476ed86fcb9bd6e2e8583fa7d31f40ea8253828e8ec557494022062464d5b18009799ad2da29eb3434e39a337b92da8782110c4eff88cb189cc0a4147304402207dda8c8c17b45d59f9db2dd2c9100e199055efb9d0ae9d8288b89343e40f07320220049f93711440f3430758296e5557db9a1f6f8cdb18ecd86994ed42da932fd00c41483045022100e33a551d632b8d011160adad33cbe9313398f4eda81a4638f5b882e24df3b3ab02201499477ce35e4fe2dbb068308cf74990cbb51fa6ed923cf2f68dac5e010744c74147304402200dbc8ad06836f0a24d60da54fb2afb8db854864e5ca1bb4d982fde792500c6330220720d6f7246c23e5edf4770fbbb0e5c3680e72204be28ce2491ee9442fb62b0724147304402206f858c771e95ca1e4fac2e5580ca5b989a2ac447741154189fb99f044839eee0022049aa497292adadb2ffbdbb10a2d997f1210a0e4aa1acd354551e972db2fed00841004cf914553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768ffffffff01401f0000000000001976a91499c7e0b48a05cd6024b22cd490fcee30aa51d86288ac00000000"
}
```

## How operators convert UTXO to a new operator set (with CashScript SDK)

We use the same function "redeemOrCovert" for redeeming cc-UTXO and converting it to a new cc-UTXO controlled by a new operator set. So the process of coverting is almost the same as the redeeming process that has been introduced.

First we prepare a new operator set (by modifying the cc-covenant-test.ts script):

```typescript
const operatorKeyPairs = [...Array(10).keys()]
    .map(x => bitbox.HDNode.derive(hdNode, x + 1000)) // modify the number and you'll get a new operator set.
    .map(n => bitbox.HDNode.toKeyPair(n));
const operatorWIFs = operatorKeyPairs.map(k => bitbox.ECPair.toWIF(k));
const operatorPks = operatorKeyPairs.map(k => bitbox.ECPair.toPublicKey(k));
const operatorPubkeysHash = bitbox.Crypto.hash160(Buffer.concat(operatorPks))
```

And execute cc-covenant-test.ts

```
operatorWIFs: [
  'L46MziScuuDu4EWo6NUnn5JqbVnGC9i5Nd3c9SRRdSGsoAYo1dfw',
  'KwaRF8Qo81vcZZj29HhZGZ21Sp6fUZSmdgnkAVghN7iYBYg1Ew52',
  'KziNJKrUqoTuo9H9Wb5YXHzsg4vDQ7883wnE6SJsSbFzzaYFWRyF',
  'L2k6QvWXT7ZmV9VZQ4fABi1waeGjupwKtsVFzewb4KbYSXLLiRH7',
  'KzQrseYXBKengmXCzH472YXgr9a6ARrsxyKy2oT1BiQcvZzyHM5z',
  'L2QQvmAuEvzJvmRGGnDLZ7Et3CGtCkrSAgH7e6gzuQhjipGacE3f',
  'L1UZsbuyby7NW9qC5WHxtVVi5grdP2a5RaDuRnyge4cLKSejGHH8',
  'L2SLqnTRLmNiQEz3M2YKEsLjqqi8omErZd7xBJKopWZUQje44DVN',
  'L5fURfE4j8PxC6haZ7YShdX2FwvqRphW6834PQDXCMyV5BLdTcyC',
  'L4WNv5fuA2TpaSHuvvcU445qEpXB4GCyzj2uD55tu6mQPo1NJ4jk'
]
operatorPks: [
  '03b027f1a8faa455ba42b2e8d898c28530835b33985e0ec45fdb6a4a9ce2eba06e',
  '02036a24560d3892a68a2a839952e41eea9499223e45032a1f1f0eb06cb33b5b0b',
  '02d452825042d8b86d038c39143521dbecd6d3c4d102d69bf16e6f2feb28526866',
  '037e38fc889954f0916a53f33badb8bc9f02d64eac516d0822fc440fa3d52041aa',
  '02f03ad456b4f6b71037fe668f704e4d0ea4c29b72a913a8a3cc0601e937ca73a7',
  '02adf4bd0fa7413b0e79e5e49c0a239de768a400b58d25d856178fd1c640c26302',
  '021a4c0ac1a3198172f0855d6d8cd278cd6a111816dbcc8de5331b60142ee1babf',
  '037ab9aebb2ebfc2aef39f67952ce63a3f264eea76f22e986e573d338eca27a8cc',
  '024841324c9007d6dd3f641862aa2fbc981db444797369e32bc16ae8df0166d5c1',
  '02516d07ed1eadf9a19ac5b723c7030d913c01475e923c7d08c805312491debab3'
]
operatorPubkeysHash: 57a158339cd184037a5b27d3033cb721713f27c3
monitorWIFs: [
  'L4GUc8432jgYMVxa1UhF1UC9Mxer5N7exdhbVLugZgWsR29U2pcw',
  'Kxr5EpWHx2WB5TKXRqqZVPNnEqB7zisXaRS6QgVTMGogzua9JFjP',
  'L2M9cNJ7oQeHMnBVFyDZPhGAGNB3v6swcX1xRiYUPj7Fpcjnv3UV'
]
monitorPks: [
  '024a899d685daf6b1999a5c8f2fd3c9ed640d58e92fd0e00cf87cacee8ff1504b8',
  '0374ac9ab3415253dbb7e29f46a69a3e51b5d2d66f125b0c9f2dc990b1d2e87e17',
  '024cc911ba9d2c7806a217774618b7ba4848ccd33fe664414fc3144d144cdebf7b'
]
monitorPubkeysHash: 27c4ca4766591e6bb8cd71b83143946c53eaf9a3
----------
redeemScriptHex: 1457a158339cd184037a5b27d3033cb721713f27c31427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768
>> redeemScriptHash: ae2c75b69475fe48a15f1a838b5238f4cc54bd58
>> cash addr: bchtest:pzhzcadkj36luj9ptudg8z6j8r6vc49atqqhxjyaf3
>> old addr: 2N98ApnTz6Ew7tS4CdbgquUpmvT1S5BG3dx
----------
```

Pleae note the new pubkeys of operators:

```
operatorPks: [
  '03b027f1a8faa455ba42b2e8d898c28530835b33985e0ec45fdb6a4a9ce2eba06e',
  '02036a24560d3892a68a2a839952e41eea9499223e45032a1f1f0eb06cb33b5b0b',
  '02d452825042d8b86d038c39143521dbecd6d3c4d102d69bf16e6f2feb28526866',
  '037e38fc889954f0916a53f33badb8bc9f02d64eac516d0822fc440fa3d52041aa',
  '02f03ad456b4f6b71037fe668f704e4d0ea4c29b72a913a8a3cc0601e937ca73a7',
  '02adf4bd0fa7413b0e79e5e49c0a239de768a400b58d25d856178fd1c640c26302',
  '021a4c0ac1a3198172f0855d6d8cd278cd6a111816dbcc8de5331b60142ee1babf',
  '037ab9aebb2ebfc2aef39f67952ce63a3f264eea76f22e986e573d338eca27a8cc',
  '024841324c9007d6dd3f641862aa2fbc981db444797369e32bc16ae8df0166d5c1',
  '02516d07ed1eadf9a19ac5b723c7030d913c01475e923c7d08c805312491debab3'
]
operatorPubkeysHash: 57a158339cd184037a5b27d3033cb721713f27c3
```

And the new P2SH address:




```
bchtest:pzhzcadkj36luj9ptudg8z6j8r6vc49atqqhxjyaf3
```

Then we prepare another UTXO:

```
$ ts-node p2pkh.ts bchtest:pplmykcc2lale6j6fg4ejsdtlhut6sc08q7uv8pxhm 10000
contract address: bchtest:pzp7kyf26k2963rre49ge4ygrl9ds3uv0c49jfrr3v
contract balance: 77287985
transaction details: {
  "inputs": [
    {
      "outpointIndex": 1,
      "outpointTransactionHash": "<Uint8Array: 0xade21da6dda4f8f965a53ff876aa3dde9ac22f861b3a5caada60ac37c3425dce>",
      "sequenceNumber": 4294967294,
      "unlockingBytecode": "<Uint8Array: 0x412b47f80e1754d2c6e79adc02d6b6dc229f563d40e5548912b7ff35b892233b02881c500aab3d3e694b7b188c86f051ecfb8a197ddcf7918472528d67ffa76bfc41210380690473f0f8dcd6f3196e044d4fc160c44597315ccd6a42117f1d6f56cc960819143ed2b14d2418fdf1b384abbf9bbe4a9b9524ca6178a988ac>"
    }
  ],
  "locktime": 1511584,
  "outputs": [
    {
      "lockingBytecode": "<Uint8Array: 0xa9147fb25b1857fbfcea5a4a2b9941abfdf8bd430f3887>",
      "satoshis": "<Uint8Array: 0x1027000000000000>"
    },
    {
      "lockingBytecode": "<Uint8Array: 0xa91483eb112ad5945d4463cd4a8cd4881fcad8478c7e87>",
      "satoshis": "<Uint8Array: 0x68f11e0400000000>"
    }
  ],
  "version": 2,
  "txid": "ba9f3ca09b8a8ae54f5482f90d3562078586364d306e372cfa471fa4ca54652b",
  "hex": "0200000001ce5d42c337ac60daaa5c3a1b862fc29ade3daa76f83fa565f9f8a4dda61de2ad010000007e412b47f80e1754d2c6e79adc02d6b6dc229f563d40e5548912b7ff35b892233b02881c500aab3d3e694b7b188c86f051ecfb8a197ddcf7918472528d67ffa76bfc41210380690473f0f8dcd6f3196e044d4fc160c44597315ccd6a42117f1d6f56cc960819143ed2b14d2418fdf1b384abbf9bbe4a9b9524ca6178a988acfeffffff02102700000000000017a9147fb25b1857fbfcea5a4a2b9941abfdf8bd430f388768f11e040000000017a91483eb112ad5945d4463cd4a8cd4881fcad8478c7e87a0101700"
}
```

Let's put it together:

```typescript
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

  // 重点看下面这两行
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
```

Following is the tx [details](https://www.blockchain.com/bch-testnet/tx/7106656d2013e63345441b2a3bcb24c0b72dd90ba04b829bbf3be772c9329f29)：

```
convertByOperators...
contract UTXOs  : [
  {
    txid: 'ba9f3ca09b8a8ae54f5482f90d3562078586364d306e372cfa471fa4ca54652b',
    vout: 0,
    satoshis: 10000,
    height: 1511586
  }
]
transaction details: {
  "inputs": [
    {
      "outpointIndex": 0,
      "outpointTransactionHash": "<Uint8Array: 0xba9f3ca09b8a8ae54f5482f90d3562078586364d306e372cfa471fa4ca54652b>",
      "sequenceNumber": 4294967294,
      "unlockingBytecode": "<Uint8Array: 0x1457a158339cd184037a5b27d3033cb721713f27c31427c4ca4766591e6bb8cd71b83143946c53eaf9a32103883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f82432103bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca210386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d2102fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873210271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c210394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af121038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af52103fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e421035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd82102d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd6994483045022100da71035a60844b1cfc94e5c5893b5c05fa485dd8f2aa0c3ddf4adf6bdc79a5a502200b6e5c6ce8cbe8dac0ec967a73eda15370d2475890d858cd400781441363d5d54147304402201609927a7a4fb610ce175daddad164e0d91987c74f2a66ce142e881a7bc0efe802200c9e0870a182550690c50d8cb70d3119b2dc1dbf932eb0ebbe6d37d773963cab41473044022072b855faac8e14860a7fcfbe421435934346be684a5ac855efbceeeaff0b2998022037c72565850d6f8974191327a5c33f87c944648f592e7b3e1291f3ba657b02d9414730440220117535312284088e5872c723ddbc66530ffab5548f32228810f5bc53b76c53110220012bf6bf8b4bd4c9f5c5a83347af81aa297a0c597e6f99ee3e23abb96e5e86ab41483045022100c702deb1c32df3a75571356b6b98d588fda16d6835a5a95402ac1d3c2bffdc4d0220325231de03b0bac3863fd02efe2da294212e389ce412e6e4356f0de142234d70414830450221009cd14d49cbddcb7de5268c51685d42c8451d15fd56151671d5bea1266177c817022001fc372c8b7a29a923f8ee3f44443df5990ecc614c23a1e3b675fc0ac4870aa741473044022008fd154a74fb144f282b4e1ea51e7a0740b2a793d27afe5b8ad3353448775acc022014cc728b00091c5ba75370fdc09e846fcf8d2b4ec1827b4bb98dedc0468be18741004cf914553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768>"
    }
  ],
  "locktime": 1511587,
  "outputs": [
    {
      "lockingBytecode": "<Uint8Array: 0xa914ae2c75b69475fe48a15f1a838b5238f4cc54bd5887>",
      "satoshis": "<Uint8Array: 0x401f000000000000>"
    }
  ],
  "version": 2,
  "txid": "7106656d2013e63345441b2a3bcb24c0b72dd90ba04b829bbf3be772c9329f29",
  "hex": "02000000012b6554caa41f47fa2c376e304d3686850762350df982544fe58a8a9ba03c9fba00000000fd75041457a158339cd184037a5b27d3033cb721713f27c31427c4ca4766591e6bb8cd71b83143946c53eaf9a32103883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f82432103bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca210386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d2102fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873210271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c210394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af121038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af52103fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e421035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd82102d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd6994483045022100da71035a60844b1cfc94e5c5893b5c05fa485dd8f2aa0c3ddf4adf6bdc79a5a502200b6e5c6ce8cbe8dac0ec967a73eda15370d2475890d858cd400781441363d5d54147304402201609927a7a4fb610ce175daddad164e0d91987c74f2a66ce142e881a7bc0efe802200c9e0870a182550690c50d8cb70d3119b2dc1dbf932eb0ebbe6d37d773963cab41473044022072b855faac8e14860a7fcfbe421435934346be684a5ac855efbceeeaff0b2998022037c72565850d6f8974191327a5c33f87c944648f592e7b3e1291f3ba657b02d9414730440220117535312284088e5872c723ddbc66530ffab5548f32228810f5bc53b76c53110220012bf6bf8b4bd4c9f5c5a83347af81aa297a0c597e6f99ee3e23abb96e5e86ab41483045022100c702deb1c32df3a75571356b6b98d588fda16d6835a5a95402ac1d3c2bffdc4d0220325231de03b0bac3863fd02efe2da294212e389ce412e6e4356f0de142234d70414830450221009cd14d49cbddcb7de5268c51685d42c8451d15fd56151671d5bea1266177c817022001fc372c8b7a29a923f8ee3f44443df5990ecc614c23a1e3b675fc0ac4870aa741473044022008fd154a74fb144f282b4e1ea51e7a0740b2a793d27afe5b8ad3353448775acc022014cc728b00091c5ba75370fdc09e846fcf8d2b4ec1827b4bb98dedc0468be18741004cf914553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768feffffff01401f00000000000017a914ae2c75b69475fe48a15f1a838b5238f4cc54bd5887a3101700"
}
```

Check the output's lockingBytecode, we can find it's owned by a new operator set:

```
OP_HASH160(0xa9)
OP_PUSHNEXT20(0x14) 0xae2c75b69475fe48a15f1a838b5238f4cc54bd58
OP_EQUAL(0x87)
```

The input's unlockingBytecode is really encoded with the newOperatorsPbukeysHash:

```
OP_PUSHNEXT20(0x14) 0x57a158339cd184037a5b27d3033cb721713f27c3 # Please NOTE HERE! the new newOperatorsPbukeysHash
OP_PUSHNEXT20(0x14) 0x27c4ca4766591e6bb8cd71b83143946c53eaf9a3
OP_PUSHNEXT33(0x21) 0x03883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f8243
OP_PUSHNEXT33(0x21) 0x03bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca
OP_PUSHNEXT33(0x21) 0x0386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d
OP_PUSHNEXT33(0x21) 0x02fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873
OP_PUSHNEXT33(0x21) 0x0271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c
OP_PUSHNEXT33(0x21) 0x0394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af1
OP_PUSHNEXT33(0x21) 0x038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af5
OP_PUSHNEXT33(0x21) 0x03fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e4
OP_PUSHNEXT33(0x21) 0x035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd8
OP_PUSHNEXT33(0x21) 0x02d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd6994
OP_PUSHNEXT72(0x48) 0x3045022100da71035a60844b1cfc94e5c5893b5c05fa485dd8f2aa0c3ddf4adf6bdc79a5a502200b6e5c6ce8cbe8dac0ec967a73eda15370d2475890d858cd400781441363d5d541
OP_PUSHNEXT71(0x47) 0x304402201609927a7a4fb610ce175daddad164e0d91987c74f2a66ce142e881a7bc0efe802200c9e0870a182550690c50d8cb70d3119b2dc1dbf932eb0ebbe6d37d773963cab41
OP_PUSHNEXT71(0x47) 0x3044022072b855faac8e14860a7fcfbe421435934346be684a5ac855efbceeeaff0b2998022037c72565850d6f8974191327a5c33f87c944648f592e7b3e1291f3ba657b02d941
OP_PUSHNEXT71(0x47) 0x30440220117535312284088e5872c723ddbc66530ffab5548f32228810f5bc53b76c53110220012bf6bf8b4bd4c9f5c5a83347af81aa297a0c597e6f99ee3e23abb96e5e86ab41
OP_PUSHNEXT72(0x48) 0x3045022100c702deb1c32df3a75571356b6b98d588fda16d6835a5a95402ac1d3c2bffdc4d0220325231de03b0bac3863fd02efe2da294212e389ce412e6e4356f0de142234d7041
OP_PUSHNEXT72(0x48) 0x30450221009cd14d49cbddcb7de5268c51685d42c8451d15fd56151671d5bea1266177c817022001fc372c8b7a29a923f8ee3f44443df5990ecc614c23a1e3b675fc0ac4870aa741
OP_PUSHNEXT71(0x47) 0x3044022008fd154a74fb144f282b4e1ea51e7a0740b2a793d27afe5b8ad3353448775acc022014cc728b00091c5ba75370fdc09e846fcf8d2b4ec1827b4bb98dedc0468be18741
OP_0(0x00)
OP_PUSHDATA1(0x4c) 0xf9 0x14553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768
```

## How operators convert UTXO to a new operator set (with Golang)

Prepare another UTXO:

```
$ ts-node p2pkh.ts bchtest:pplmykcc2lale6j6fg4ejsdtlhut6sc08q7uv8pxhm 10000
contract address: bchtest:pzp7kyf26k2963rre49ge4ygrl9ds3uv0c49jfrr3v
contract balance: 77277742
transaction details: {
  "inputs": [
    {
      "outpointIndex": 1,
      "outpointTransactionHash": "<Uint8Array: 0xba9f3ca09b8a8ae54f5482f90d3562078586364d306e372cfa471fa4ca54652b>",
      "sequenceNumber": 4294967294,
      "unlockingBytecode": "<Uint8Array: 0x4130335519e9059ab6474457013be0858d81810d0ce1ec7ff8cd00a3aca28f486630ba6108d521fd91a26850c52d922d0b7b1d058308c97dc3783d34362cb99a5741210380690473f0f8dcd6f3196e044d4fc160c44597315ccd6a42117f1d6f56cc960819143ed2b14d2418fdf1b384abbf9bbe4a9b9524ca6178a988ac>"
    }
  ],
  "locktime": 1511589,
  "outputs": [
    {
      "lockingBytecode": "<Uint8Array: 0xa9147fb25b1857fbfcea5a4a2b9941abfdf8bd430f3887>",
      "satoshis": "<Uint8Array: 0x1027000000000000>"
    },
    {
      "lockingBytecode": "<Uint8Array: 0xa91483eb112ad5945d4463cd4a8cd4881fcad8478c7e87>",
      "satoshis": "<Uint8Array: 0x65c91e0400000000>"
    }
  ],
  "version": 2,
  "txid": "f7aed2149ab8eeb18c315273865370008ccaa78924736dbb2a407709c97e2a85",
  "hex": "02000000012b6554caa41f47fa2c376e304d3686850762350df982544fe58a8a9ba03c9fba010000007e4130335519e9059ab6474457013be0858d81810d0ce1ec7ff8cd00a3aca28f486630ba6108d521fd91a26850c52d922d0b7b1d058308c97dc3783d34362cb99a5741210380690473f0f8dcd6f3196e044d4fc160c44597315ccd6a42117f1d6f56cc960819143ed2b14d2418fdf1b384abbf9bbe4a9b9524ca6178a988acfeffffff02102700000000000017a9147fb25b1857fbfcea5a4a2b9941abfdf8bd430f388765c91e040000000017a91483eb112ad5945d4463cd4a8cd4881fcad8478c7e87a5101700"
}
```

The flow in golang：

```golang
func Test_ConvertByOperatorsTx(t *testing.T) {
    c, err := NewCcCovenant(redeemScriptWithoutConstructorArgs, operatorPks, monitorPks, 2000, &chaincfg.TestNet3Params)
    require.NoError(t, err)

    txid := "f7aed2149ab8eeb18c315273865370008ccaa78924736dbb2a407709c97e2a85"
    vout := uint32(0)
    inAmt := int64(10000)
    //outAmt := int64(8000) // gasFee = 2000

    unsignedTx, sigHash, err := c.GetConvertByOperatorsTxSigHash(txid, vout, inAmt, operatorPks2, monitorPks)
    require.NoError(t, err)

    var sigs [][]byte
    hashType := txscript.SigHashAll | txscript.SigHashForkID
    for i := 0; i < 7; i++ {
        sig, err := SignCcCovenantTxSigHashECDSA(operatorWIFs[i], sigHash, hashType)
        require.NoError(t, err, i)
        sigs = append(sigs, sig)
    }

    rawTx, err := c.FinishConvertByOperatorsTx(unsignedTx, sigs, operatorPks2, monitorPks)
    require.NoError(t, err)
    println("rawTx:", rawTx)

    expectedTxHex := "0200000001852a7ec90977402abb6d732489a7ca8c007053867352318cb1eeb89a14d2aef700000000fd74041457a158339cd184037a5b27d3033cb721713f27c31427c4ca4766591e6bb8cd71b83143946c53eaf9a32103883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f82432103bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca210386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d2102fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873210271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c210394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af121038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af52103fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e421035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd82102d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd699447304402202153a9426e87753de35ece28543919eea82bb46532aae32d2b13641a826951d2022067903db92947ad2e784f866f14a027da7202ece8f3145a2c3387e836e25b63ea41483045022100904fbecb3e35780adea3645bf2f2a37cb61b43fc100bf447ce16366e0e9009150220487d9f36218cbff313e3d2e4a9ebd20a471f2494e4e402571d6cade2506ad01341473044022043bf8c4b5675c16e957339e167f9c231ae60013445e6a4e82f1c9640d5c7291c02207fd7b6b784642e0500865b1b68cd866ee1cfb9fa548729343b3ddf2c4ec327c74147304402203441f38bf20cea13d1ee7011cf3156667d46161c9751eb54bd928a7be5c5f715022075e24d9da97d66a1909a5c6559ad4b51f21548d4db2e0fef1ce9b312639d179e4147304402200e5a734c4ad82a274a95d1aaa5bb78e526b52c566a44a702018d08f7766265df0220690b47af5f3cf1408fe7e393e2308ef769c37e4d5b470f5359f775e106574cf641473044022047ffba19d10f5924edf418a5f1c538a5d7677e5ad896d0c7546da1e80dec697602204ad3c60914704ce05bd38b1b3f3dcad9ff5ffa5143e49956d9caac41bf25b1e941483045022100a5ee673171e3005b92bb5394efc41fbf5b685b84ac1b2f5ad1f7cfd8af63208d02201db58c9702f8e9e51887d0d09b5c14f4cd0c40dd9be9b4d39a31803db02da5b541004cf914553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768ffffffff01401f00000000000017a914ae2c75b69475fe48a15f1a838b5238f4cc54bd588700000000"
    require.Equal(t, expectedTxHex, rawTx)
}
```

Broadcast tx

```
$ ts-node send-raw-tx.ts 0200000001852a7ec90977402abb6d732489a7ca8c007053867352318cb1eeb89a14d2aef700000000fd74041457a158339cd184037a5b27d3033cb721713f27c31427c4ca4766591e6bb8cd71b83143946c53eaf9a32103883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f82432103bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca210386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d2102fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873210271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c210394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af121038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af52103fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e421035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd82102d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd699447304402202153a9426e87753de35ece28543919eea82bb46532aae32d2b13641a826951d2022067903db92947ad2e784f866f14a027da7202ece8f3145a2c3387e836e25b63ea41483045022100904fbecb3e35780adea3645bf2f2a37cb61b43fc100bf447ce16366e0e9009150220487d9f36218cbff313e3d2e4a9ebd20a471f2494e4e402571d6cade2506ad01341473044022043bf8c4b5675c16e957339e167f9c231ae60013445e6a4e82f1c9640d5c7291c02207fd7b6b784642e0500865b1b68cd866ee1cfb9fa548729343b3ddf2c4ec327c74147304402203441f38bf20cea13d1ee7011cf3156667d46161c9751eb54bd928a7be5c5f715022075e24d9da97d66a1909a5c6559ad4b51f21548d4db2e0fef1ce9b312639d179e4147304402200e5a734c4ad82a274a95d1aaa5bb78e526b52c566a44a702018d08f7766265df0220690b47af5f3cf1408fe7e393e2308ef769c37e4d5b470f5359f775e106574cf641473044022047ffba19d10f5924edf418a5f1c538a5d7677e5ad896d0c7546da1e80dec697602204ad3c60914704ce05bd38b1b3f3dcad9ff5ffa5143e49956d9caac41bf25b1e941483045022100a5ee673171e3005b92bb5394efc41fbf5b685b84ac1b2f5ad1f7cfd8af63208d02201db58c9702f8e9e51887d0d09b5c14f4cd0c40dd9be9b4d39a31803db02da5b541004cf914553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768ffffffff01401f00000000000017a914ae2c75b69475fe48a15f1a838b5238f4cc54bd588700000000
rawTx: ...

Transaction ID: 797c8a17f4ae5714e84d38bc480b24eb15072f0d48300b32985d3bb44fa35173
```

The tx [details](https://www.blockchain.com/bch-testnet/tx/797c8a17f4ae5714e84d38bc480b24eb15072f0d48300b32985d3bb44fa35173)：

```
{
  "inputs": [
    {
      "outpointIndex": 0,
      "outpointTransactionHash": "<Uint8Array: 0xf7aed2149ab8eeb18c315273865370008ccaa78924736dbb2a407709c97e2a85>",
      "sequenceNumber": 4294967295,
      "unlockingBytecode": "<Uint8Array: 0x1457a158339cd184037a5b27d3033cb721713f27c31427c4ca4766591e6bb8cd71b83143946c53eaf9a32103883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f82432103bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca210386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d2102fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873210271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c210394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af121038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af52103fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e421035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd82102d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd699447304402202153a9426e87753de35ece28543919eea82bb46532aae32d2b13641a826951d2022067903db92947ad2e784f866f14a027da7202ece8f3145a2c3387e836e25b63ea41483045022100904fbecb3e35780adea3645bf2f2a37cb61b43fc100bf447ce16366e0e9009150220487d9f36218cbff313e3d2e4a9ebd20a471f2494e4e402571d6cade2506ad01341473044022043bf8c4b5675c16e957339e167f9c231ae60013445e6a4e82f1c9640d5c7291c02207fd7b6b784642e0500865b1b68cd866ee1cfb9fa548729343b3ddf2c4ec327c74147304402203441f38bf20cea13d1ee7011cf3156667d46161c9751eb54bd928a7be5c5f715022075e24d9da97d66a1909a5c6559ad4b51f21548d4db2e0fef1ce9b312639d179e4147304402200e5a734c4ad82a274a95d1aaa5bb78e526b52c566a44a702018d08f7766265df0220690b47af5f3cf1408fe7e393e2308ef769c37e4d5b470f5359f775e106574cf641473044022047ffba19d10f5924edf418a5f1c538a5d7677e5ad896d0c7546da1e80dec697602204ad3c60914704ce05bd38b1b3f3dcad9ff5ffa5143e49956d9caac41bf25b1e941483045022100a5ee673171e3005b92bb5394efc41fbf5b685b84ac1b2f5ad1f7cfd8af63208d02201db58c9702f8e9e51887d0d09b5c14f4cd0c40dd9be9b4d39a31803db02da5b541004cf914553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768>"
    }
  ],
  "locktime": 0,
  "outputs": [
    {
      "lockingBytecode": "<Uint8Array: 0xa914ae2c75b69475fe48a15f1a838b5238f4cc54bd5887>",
      "satoshis": "<Uint8Array: 0x401f000000000000>"
    }
  ],
  "version": 2,
  "txHex": "0200000001852a7ec90977402abb6d732489a7ca8c007053867352318cb1eeb89a14d2aef700000000fd74041457a158339cd184037a5b27d3033cb721713f27c31427c4ca4766591e6bb8cd71b83143946c53eaf9a32103883b732620e238e74041e5fab900234dc80f7a48d56a1bf41e8523c4661f82432103bfe6f6ecb5e10662481aeb6f6408db2a32b9b86a660acbb8c5374dbb976e53ca210386f450b1bee3b220c6a9a25515f15f05bd80a23e5f707873dfbac52db933b27d2102fbbc3870035c2ee30cfa3102aff15e58bdfc0d0f95998cd7e1eeebc09cdb6873210271ea0c254ebbb7ed78668ba8653abe222b9f7177642d3a75709d95912a8d9d2c210394ec324d59305638ead14b4f4da9a50c793f1e328e180f92c04a4990bb573af121038fd3d33474e1bd453614f85d8fb1edecae92255867d18a9048669119fb710af52103fdec69ef6ec640264045229ca7cf0f170927b87fc8d2047844f8a766ead467e421035c0a0cb8987290ea0a7a926e8aa8978ac042b4c0be8553eb4422461ce1a17cd82102d86b49e3424e557beebf67bd06842cdb88e314c44887f3f265b7f81107dd699447304402202153a9426e87753de35ece28543919eea82bb46532aae32d2b13641a826951d2022067903db92947ad2e784f866f14a027da7202ece8f3145a2c3387e836e25b63ea41483045022100904fbecb3e35780adea3645bf2f2a37cb61b43fc100bf447ce16366e0e9009150220487d9f36218cbff313e3d2e4a9ebd20a471f2494e4e402571d6cade2506ad01341473044022043bf8c4b5675c16e957339e167f9c231ae60013445e6a4e82f1c9640d5c7291c02207fd7b6b784642e0500865b1b68cd866ee1cfb9fa548729343b3ddf2c4ec327c74147304402203441f38bf20cea13d1ee7011cf3156667d46161c9751eb54bd928a7be5c5f715022075e24d9da97d66a1909a5c6559ad4b51f21548d4db2e0fef1ce9b312639d179e4147304402200e5a734c4ad82a274a95d1aaa5bb78e526b52c566a44a702018d08f7766265df0220690b47af5f3cf1408fe7e393e2308ef769c37e4d5b470f5359f775e106574cf641473044022047ffba19d10f5924edf418a5f1c538a5d7677e5ad896d0c7546da1e80dec697602204ad3c60914704ce05bd38b1b3f3dcad9ff5ffa5143e49956d9caac41bf25b1e941483045022100a5ee673171e3005b92bb5394efc41fbf5b685b84ac1b2f5ad1f7cfd8af63208d02201db58c9702f8e9e51887d0d09b5c14f4cd0c40dd9be9b4d39a31803db02da5b541004cf914553fac4027a7a3c4e8a3eaea75aab173d3c8144b1427c4ca4766591e6bb8cd71b83143946c53eaf9a35279009c635a795c797e5d797e5e797e5f797e60797e0111797e0112797e0113797e0114797ea952798800717c567a577a587a597a5a7a575c7a5d7a5e7a5f7a607a01117a01127a01137a01147a01157a5aafc3519dc4519d00cc00c602d007949d5379879154797b87919b63011453797e01147e52797ec1012a7f777e02a91478a97e01877e00cd78886d686d7551677b519d547956797e57797ea98800727c52557a567a577a53afc0009d00cc00c69d024065b27501147b7ec101157f777e02a9147ca97e01877e00cd877768ffffffff01401f00000000000017a914ae2c75b69475fe48a15f1a838b5238f4cc54bd588700000000"
}
```
