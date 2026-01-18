
# **mini‑bounty challenge v3**

your goal is to break the ciphertext `seed.ct` which contains string data in the following format:

`mnemonic: (mnemonic phrase for octra wallet, 12 words), number: (numeric value to be sent in the "message" field of a transaction on the octra network)`

you can use any available tools to decrypt this ciphertext, try to extract the parameter R from the equation and try to recover its contents

once you recover the seed phrase, you will gain access to the wallet (which currently holds **30k OCT**): [oct7rAAiRhdRvKChDQrTJEAUqM9M9sfTBGQsacqME18xe1V](https://octrascan.io/addresses/oct7rAAiRhdRvKChDQrTJEAUqM9M9sfTBGQsacqME18xe1V)

then, by sending a transaction with any amount and a message (which you can also recover from the ciphertext, along with your eth address) to this address: `octHLvpfkP3NKSZ3tfAMYV1jzbGR7KtnVReish6sSXdGfst`, you will receive access to the ethereum address holding **4444.4444 USDT** in response: [0xa0b038b20b4633ffF5cDE2bDEfB63d6E1FD8C2e2](https://etherscan.io/address/0xa0b038b20b4633ffF5cDE2bDEfB63d6E1FD8C2e2)

**you should also create an issue ticket for this repository and tell us how you managed to find the information in the seed file**

ps: please avoid pointless slop reports that serve no purpose, only publish a ticket after you've recovered seed phrase and sent a tx with the secret num

for your convenience, `bounty3_test.cpp` fully demonstrates the encryption mechanics for `const std::string seed`, and for decoding you can use `decode_ct.cpp`.

## build & test
```bash
g++ -std=c++17 -O2 -march=native -I./include -o build/bounty3_test tests/bounty3_test.cpp
./build/bounty3_test

g++ -std=c++17 -O2 -march=native -I./include -o build/decode_ct tests/decode_ct.cpp
./build/decode_ct bounty3_data
```

## checksums
```
692ea043daf5d8910a216a0cff80131fa6a06fe0133ac0f0b91a0f0570378877  params.json
a3cb3b153211f1086fde20309106f979477985f679288cbfb60cf553bdc6bca0  pk.bin
304c5c9160fc374ecb42fba7641e21500cb729d031f9cbfb33c35a000229e474  seed.ct
```
good luck in your tests and attempts