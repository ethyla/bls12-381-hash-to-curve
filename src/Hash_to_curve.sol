// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {console} from "forge-std/Test.sol";

contract Hash_to_curve {
    uint8 HTF_L = 64;

    //         function HashToG1(msg)
    //     fieldElement0 = HashToBase(msg, 0x00, 0x01)
    //     fieldElement1 = HashToBase(msg, 0x02, 0x03)
    //     curveElement0 = BaseToG1(fieldElement0)
    //     curveElement1 = BaseToG1(fieldElement1)
    //     g1Element = ECAdd(curveElement0, curveElement1)
    //     return g1Element
    // end function
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

    // hash_to_field(msg, count)
    // Parameters:
    // - DST, a domain separation tag (see Section 3.1).
    // - F, a finite field of characteristic p and order q = p^m.
    // - p, the characteristic of F (see immediately above).
    // - m, the extension degree of F, m >= 1 (see immediately above).
    // - L = ceil((ceil(log2(p)) + k) / 8), where k is the security
    //   parameter of the suite (e.g., k = 128).
    // - expand_message, a function that expands a byte string and
    //   domain separation tag into a uniformly random byte string
    //   (see Section 5.3).
    // Input:
    // - msg, a byte string containing the message to hash.
    // - count, the number of elements of F to output.
    // Output:
    // - (u_0, ..., u_(count - 1)), a list of field elements.
    // Steps:
    // 1. len_in_bytes = count * m * L
    // 2. uniform_bytes = expand_message(msg, DST, len_in_bytes)
    // 3. for i in (0, ..., count - 1):
    // 4.   for j in (0, ..., m - 1):
    // 5.     elm_offset = L * (j + i * m)
    // 6.     tv = substr(uniform_bytes, elm_offset, L)
    // 7.     e_j = OS2IP(tv) mod p
    // 8.   u_i = (e_0, ..., e_(m - 1))
    // 9. return (u_0, ..., u_(count - 1))
    function hash_to_field_fq2(
        bytes calldata message,
        uint8 count,
        bytes memory domain
    ) public view returns (bytes[][] memory) {
        uint8 M = 2;
        uint16 len_in_bytes = uint16(count) * M * HTF_L; // HTF_L is 64
        // this field_modulus as hex 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
        bytes
            memory modulus = hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
        bytes
            memory one = hex"0000000000000000000000000000000000000000000000000000000000000001";

        bytes memory pseudo_random_bytes = expand_msg_xmd(
            message,
            len_in_bytes,
            domain
        );

        bytes[][] memory u = new bytes[][](count);
        for (uint i = 0; i < count; i++) {
            bytes[] memory e = new bytes[](M);
            for (uint j = 0; j < M; j++) {
                uint256 offset = HTF_L * (j + i * M);

                bytes memory tv = new bytes(HTF_L);

                for (uint k = 0; k < HTF_L; k++) {
                    tv[k] = pseudo_random_bytes[k + offset];
                }
                // console.log("tv");
                // console.logBytes(tv);
                // console.logBytes(modulus);
                // console.logBytes(_modexp(tv, one, modulus));
                e[j] = _modexp(tv, one, modulus);
            }
            u[i] = e;
        }
        return u;
    }

    // expand_message_xmd(msg, DST, len_in_bytes)

    // Parameters:
    // - H, a hash function (see requirements above).
    // - b_in_bytes, b / 8 for b the output size of H in bits.
    //   For example, for b = 256, b_in_bytes = 32.
    // - s_in_bytes, the input block size of H, measured in bytes (see
    //   discussion above). For example, for SHA-256, s_in_bytes = 64.

    // Input:
    // - msg, a byte string.
    // - DST, a byte string of at most 255 bytes.
    //   See below for information on using longer DSTs.
    // - len_in_bytes, the length of the requested output in bytes,
    //   not greater than the lesser of (255 * b_in_bytes) or 2^16-1.

    // Output:
    // - uniform_bytes, a byte string.

    // Steps:
    // 1.  ell = ceil(len_in_bytes / b_in_bytes)
    // 2.  ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
    // 3.  DST_prime = DST || I2OSP(len(DST), 1)
    // 4.  Z_pad = I2OSP(0, s_in_bytes)
    // 5.  l_i_b_str = I2OSP(len_in_bytes, 2)
    // 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
    // 7.  b_0 = H(msg_prime)
    // 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    // 9.  for i in (2, ..., ell):
    // 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
    // 11. uniform_bytes = b_1 || ... || b_ell
    // 12. return substr(uniform_bytes, 0, len_in_bytes)
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
        bytes memory msg_prime = abi.encodePacked(
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
        b[1] = sha256(abi.encodePacked(b[0], hex"01", dst_prime));
        // console.log("b1");
        // console.logBytes32(b[1]);

        bytes memory pseudo_random_bytes = abi.encodePacked(b[1]);
        // console.log("pseudo_random_bytes");
        // console.logBytes(pseudo_random_bytes);

        // 9.  for i in (2, ..., ell):
        for (uint8 i = 2; i <= ell; i++) {
            // 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
            bytes memory tmp = abi.encodePacked(b[0] ^ b[i - 1]);
            tmp = abi.encodePacked(tmp, i, dst_prime);
            b[i] = sha256(tmp);

            // 11. uniform_bytes = b_1 || ... || b_ell
            pseudo_random_bytes = abi.encodePacked(
                pseudo_random_bytes,
                sha256(tmp)
            );
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
     * @param _e bytes base_inverse
     * @param _m bytes exponent
     * @param r bytes result.
     */
    function _modexp(
        bytes memory _b,
        bytes memory _e,
        bytes memory _m
    ) private view returns (bytes memory r) {
        assembly {
            let bl := mload(_b)
            let el := mload(_e)
            let ml := mload(_m)

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
            success := staticcall(
                450,
                0x4,
                add(_e, 32),
                el,
                add(freemem, size),
                el
            )

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
