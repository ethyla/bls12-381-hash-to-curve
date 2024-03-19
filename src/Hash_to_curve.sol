// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {console} from "forge-std/Test.sol";

contract Hash_to_curve {
    uint8 HTF_L = 64;

    // hash_to_curve(msg)
    // Input: msg, an arbitrary-length byte string.
    // Output: P, a point in G.
    // Steps:
    // 1. u = hash_to_field(msg, 2)
    // 2. Q0 = map_to_curve(u[0])
    // 3. Q1 = map_to_curve(u[1])
    // 4. R = Q0 + Q1              # Point addition
    // 5. P = clear_cofactor(R)
    // 6. return P
    function hash_to_curve_g1(bytes calldata message) public {}

    // Notes:
    // abi for the precompiles is bytes32 concats, so like this bytes32[4] for two points or a G2 point
    // so no length or anything. For reference a base field point is bytes32[2] (G1) and two points in the quadratic field are bytes32[8] or 256 bytes
    // addition takes a concatination of two points so G1 = bytes32[4] and G2 = bytes32[8]
    // multiplication takes the point and a concatinated int256
    // map to curve g1 takes a 64 bytes field element
    // map to curve g2 takes a 128 bytes field element
    // all operations return a single point either G1 or G2 so either 128 or 256 bytes
    // costs
    // G1 addition
    // 600 gas
    // G1 multiplication
    // 12000 gas
    // G2 addition
    // 4500 gas
    // G2 multiplication
    // 55000 gas
    // Fp-to-G1 mappign operation
    // Fp -> G1 mapping is 5500 gas.
    // Fp2-to-G2 mappign operation
    // Fp2 -> G2 mapping is 110000 gas
    // it seems we will need each of these operations exactly once
    // g1 total cost: 18100             current hash to field ca 120000 so total ca: 140000
    // g2 total cost: 169500            current hash to field ca 220000 so total ca: 390000

    function hash_to_curve_g2(bytes calldata message) public {}

    // https://datatracker.ietf.org/doc/html/rfc9380#section-5.2
    // Input:
    // - msg, a byte string containing the message to hash.
    // - count, the number of elements of F to output.
    // - DST, a domain separation tag (see Section 3.1).
    function hash_to_field_fp2(
        bytes calldata message,
        uint8 count,
        bytes memory domain
    ) public view returns (bytes[][] memory) {
        uint8 M = 2;
        // this field_modulus as hex 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
        bytes
            memory modulus = hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

        // 1. len_in_bytes = count * m * L
        uint16 len_in_bytes = uint16(count) * M * HTF_L; // HTF_L is 64

        // 2. uniform_bytes = expand_message(msg, DST, len_in_bytes)
        bytes memory pseudo_random_bytes = expand_msg_xmd(
            message,
            len_in_bytes,
            domain
        );

        bytes[][] memory u = new bytes[][](count);

        // 3. for i in (0, ..., count - 1):
        for (uint i = 0; i < count; i++) {
            bytes[] memory e = new bytes[](M);
            // 4.   for j in (0, ..., m - 1):
            for (uint j = 0; j < M; j++) {
                // 5.     elm_offset = L * (j + i * m)
                uint256 offset = HTF_L * (j + i * M);

                // 6.     tv = substr(uniform_bytes, elm_offset, L)
                bytes memory tv = new bytes(HTF_L);
                for (uint k = 0; k < HTF_L; k++) {
                    tv[k] = pseudo_random_bytes[k + offset];
                }
                // console.log("tv");
                // console.logBytes(tv);
                // console.logBytes(modulus);
                // console.logBytes(_modexp(tv, one, modulus));
                // 7.     e_j = OS2IP(tv) mod p
                e[j] = _modexp(tv, modulus);
            }
            // 8.   u_i = (e_0, ..., e_(m - 1))
            u[i] = e;
        }
        // 9. return (u_0, ..., u_(count - 1))
        return u;
    }

    function hash_to_field_fp(
        bytes calldata message,
        uint8 count,
        bytes memory domain
    ) public view returns (bytes[] memory) {
        uint8 M = 1;
        // this field_modulus as hex 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
        bytes
            memory modulus = hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

        uint16 len_in_bytes = uint16(count) * M * HTF_L; // HTF_L is 64

        bytes memory pseudo_random_bytes = expand_msg_xmd(
            message,
            len_in_bytes,
            domain
        );

        bytes[] memory u = new bytes[](count);

        for (uint i = 0; i < count; i++) {
            uint256 offset = HTF_L * (i * M);

            bytes memory tv = new bytes(HTF_L);

            for (uint k = 0; k < HTF_L; k++) {
                tv[k] = pseudo_random_bytes[k + offset];
            }

            u[i] = _modexp(tv, modulus);
        }
        return u;
    }

    // https://datatracker.ietf.org/doc/html/rfc9380#section-5.2
    // Input:
    // - msg, a byte string.
    // - DST, a byte string of at most 255 bytes.
    // - len_in_bytes, the length of the requested output in bytes,
    //   not greater than the lesser of (255 * b_in_bytes) or 2^16-1.

    // len_in_bytes is supposed to be able to be bigger but for now we just use 255  to simplify the code
    function expand_msg_xmd(
        bytes calldata message,
        uint16 len_in_bytes,
        bytes memory dst
    ) public pure returns (bytes memory) {
        // 1.  ell = ceil(len_in_bytes / b_in_bytes)
        // 2.  ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
        // b_in_bytes seems to be 32 for sha256
        // ceil the division
        uint ell = (len_in_bytes - 1) / 32 + 1;

        require(ell <= 255, "len_in_bytes too large for sha256");
        // Not really needed because of parameter type
        require(len_in_bytes <= 65535, "len_in_bytes too large");
        // no length normalizing via hashing
        require(dst.length <= 255, "dst too long");

        bytes memory dst_prime = bytes.concat(dst, bytes1(uint8(dst.length)));

        // 4.  Z_pad = I2OSP(0, s_in_bytes)
        // this should be sha256 blocksize so 64 bytes
        bytes
            memory zpad = hex"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        // 5.  l_i_b_str = I2OSP(len_in_bytes, 2)
        // length in byte string?
        bytes2 l_i_b_str = bytes2(len_in_bytes);

        // 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
        bytes memory msg_prime = bytes.concat(
            zpad,
            message,
            l_i_b_str,
            hex"00",
            dst_prime
        );
        // console.log("msg_prime");
        // console.logBytes(msg_prime);

        bytes32[] memory b = new bytes32[](ell + 1);

        // 7.  b_0 = H(msg_prime)
        b[0] = sha256(msg_prime);

        // 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        b[1] = sha256(bytes.concat(b[0], hex"01", dst_prime));
        // console.log("b1");
        // console.logBytes32(b[1]);

        bytes memory pseudo_random_bytes = bytes.concat(b[1]);
        // console.log("pseudo_random_bytes");
        // console.logBytes(pseudo_random_bytes);

        // 9.  for i in (2, ..., ell):
        for (uint8 i = 2; i <= ell; i++) {
            // 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
            bytes memory tmp = abi.encodePacked(b[0] ^ b[i - 1], i, dst_prime);
            bytes32 tmpHash = sha256(tmp);
            b[i] = tmpHash;

            // 11. uniform_bytes = b_1 || ... || b_ell
            pseudo_random_bytes = bytes.concat(pseudo_random_bytes, tmpHash);
        }
        // console.log("pseudo_random_bytes");
        // console.logBytes(pseudo_random_bytes);

        // 12. return substr(uniform_bytes, 0, len_in_bytes)
        bytes memory a = new bytes(len_in_bytes);
        for (uint i = 0; i < len_in_bytes; i++) {
            a[i] = pseudo_random_bytes[i];
        }
        return a;
    }

    // From https://github.com/firoorg/solidity-BigNumber/blob/master/src/BigNumbers.sol

    /** @notice Modular Exponentiation: Takes bytes values for base, exp, mod and calls precompile for (base^exp)%^mod
     * @dev modexp: Wrapper for built-in modexp (contract 0x5) as described here:
     *              https://github.com/ethereum/EIPs/pull/198
     *
     * @param _b bytes base
     * @param _m bytes modulus
     * @param r bytes result.
     */
    function _modexp(
        bytes memory _b,
        bytes memory _m
    ) internal view returns (bytes memory r) {
        assembly {
            let bl := mload(_b)
            let ml := mload(_m)
            let el := 0x20

            let freemem := mload(0x40) // Free memory pointer is always stored at 0x40

            mstore(freemem, bl) // arg[0] = base.length @ +0

            mstore(add(freemem, 32), el) // arg[1] = exp.length @ +32

            mstore(add(freemem, 64), ml) // arg[2] = mod.length @ +64

            // arg[3] = base.bits @ + 96
            // Use identity built-in (contract 0x4) as a cheap memcpy
            let success := staticcall(
                450,
                0x4,
                add(_b, 32),
                bl,
                add(freemem, 96),
                bl
            )

            // arg[4] = exp.bits @ +96+base.length
            let size := add(96, bl)
            mstore(add(freemem, size), 1)

            // success := staticcall(
            //     450,
            //     0x4,
            //     add(0x20, 32),
            //     el,
            //     add(freemem, size),
            //     el
            // )

            // arg[5] = mod.bits @ +96+base.length+exp.length
            size := add(size, el)
            success := staticcall(
                450,
                0x4,
                add(_m, 32),
                ml,
                add(freemem, size),
                ml
            )

            switch success
            case 0 {
                invalid()
            } //fail where we haven't enough gas to make the call

            // Total size of input = 96+base.length+exp.length+mod.length
            size := add(size, ml)
            // Invoke contract 0x5, put return value right after mod.length, @ +96
            success := staticcall(
                sub(gas(), 1350),
                0x5,
                freemem,
                size,
                add(freemem, 0x60),
                ml
            )

            switch success
            case 0 {
                invalid()
            } //fail where we haven't enough gas to make the call

            let length := ml
            let msword_ptr := add(freemem, 0x60)

            ///the following code removes any leading words containing all zeroes in the result.
            for {

            } eq(eq(length, 0x20), 0) {

            } {
                // for(; length!=32; length-=32)
                switch eq(mload(msword_ptr), 0) // if(msword==0):
                case 1 {
                    msword_ptr := add(msword_ptr, 0x20)
                } //     update length pointer
                default {
                    break
                } // else: loop termination. non-zero word found
                length := sub(length, 0x20)
            }
            r := sub(msword_ptr, 0x20)
            mstore(r, length)

            // point to the location of the return value (length, bits)
            //assuming mod length is multiple of 32, return value is already in the right format.
            mstore(0x40, add(add(96, freemem), ml)) //deallocate freemem pointer
        }
    }
}
