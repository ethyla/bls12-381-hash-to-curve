## BLS381 Hash to curve

Solidity implementation of hash to curve for the BLS381 curve.

Follows https://datatracker.ietf.org/doc/html/rfc9380

### WIP!

Working:  
expand_msg_xmd  
hash_to_field fp and fp2

needs testing:
hash_to_curve g1 and g2

### Notes

#### costs

G1 addition 600 gas
G2 addition 4500 gas  
Fp-to-G1 mapping 5500 gas
Fp2-to-G2 mapping 110000 gas  
it seems we will need each of these operations exactly once (map is used 2 times)

g1 total cost: 11600 current hash to field ca 33000 so total ca: 44600  
g2 total cost: 234500 current hash to field ca 44000 so total ca: 278500
