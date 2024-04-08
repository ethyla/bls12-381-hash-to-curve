## BLS381 Hash to curve

Solidity implementation of hash to curve for the BLS381 curve using the EIP-2537 precompiles.

Follows https://datatracker.ietf.org/doc/html/rfc9380

### Tests

`forge test`  
Runs tests against expandMsgXmd and hashToField.  
hashToCurve tests exist, but fail because foundry doesn't have EIP support yet.

`npm run testjs`  
Runs hardhat tests for hashToCurve.  
Make sure you have an execution client at `http://localhost:8545` running that supports the EIP.

All test cases are from the RFC.

### Notes

#### Costs

G1 addition 600 gas
G2 addition 4500 gas  
Fp-to-G1 mapping 5500 gas (used twice)
Fp2-to-G2 mapping 110000 gas (used twice)

g1 total cost:  
11600 (precompiles) + 31000 (current hash to field) = ca: 42600  
g2 total cost:  
234500 (precompiles) + 44000 (current hash to field) =ca: 278500

#### readable version

This is an old version that follows the RFC very literal and is therefore very easy to understand.

#### EIPTester

Very simple test to see wether the RPC has EIP-2537 enabled.

### Disclaimer

No guarantee for the correctness of the implementation.
