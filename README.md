## BLS381 Hash to curve

Solidity implementation of hash to curve for the BLS381 curve.

Follows https://datatracker.ietf.org/doc/html/rfc9380

### WIP!

Working:  
expand_msg_xmd  
hash_to_field fp and fp2

needs testing:
hash_to_curve g1

Missing:
clear cofactor for G2

### Notes

#### costs

G1 addition
600 gas
G1 multiplication
12000 gas
G2 addition
4500 gas
G2 multiplication
55000 gas
Fp-to-G1 mappign operation
Fp -> G1 mapping is 5500 gas.
Fp2-to-G2 mappign operation
Fp2 -> G2 mapping is 110000 gas
it seems we will need each of these operations exactly once (map is used 2 times)

g1 total cost: 23600 current hash to field ca 33000 so total ca: 56600
g2 total cost: 179500 current hash to field ca 44000 so total ca: 223500

The g2 calculation is naive and it will be way more expensive as just a simple scalar mul can't be used for the cofactor clearing as the scalar is way to big for the precompile.
That means a an optimization such as Budroni-Pintore needs be used. Sadly it's not exactly a gas optimazation and will result in way higher costs than calculated above.
