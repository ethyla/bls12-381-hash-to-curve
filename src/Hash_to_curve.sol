// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {console} from "forge-std/Test.sol";

struct Field_point {
    bytes u;
}

struct Field_point_2 {
    bytes u;
    bytes u_I;
}

struct G1_point {
    bytes x;
    bytes y;
}

struct G2_point {
    bytes x;
    bytes x_I;
    bytes y;
    bytes y_I;
}

contract Hash_to_curve {
    // Input: msg, an arbitrary-length byte string.
    // Output: P, a point in G.
    function hash_to_curve_g1(
        bytes calldata message,
        bytes calldata dst
    ) external view returns (G1_point memory) {
        // 1. u = hash_to_field(msg, 2)
        Field_point[2] memory u = hash_to_field_fp(message, dst);
        // 2. Q0 = map_to_curve(u[0])
        bytes32[4] memory Q0 = map_fp_to_g1(u[0].u);
        // 3. Q1 = map_to_curve(u[1])
        bytes32[4] memory Q1 = map_fp_to_g1(u[1].u);
        // 4. R = Q0 + Q1              # Point addition
        bytes32[4] memory R = add_g1(Q0, Q1);
        // 5. P = clear_cofactor(R)
        // Not needed as map fp to g1 already does it
        // 6. return P
        G1_point memory P = G1_point({
            x: bytes.concat(R[0], R[1]),
            y: bytes.concat(R[2], R[3])
        });
        return P;
    }

    function hash_to_curve_g2(
        bytes calldata message,
        bytes calldata dst
    ) external view returns (G2_point memory) {
        // 1. u = hash_to_field(msg, 2)
        Field_point_2[2] memory u = hash_to_field_fp2(message, dst);
        // 2. Q0 = map_to_curve(u[0])
        bytes32[8] memory Q0 = map_fp2_to_g2(u[0]);
        // 3. Q1 = map_to_curve(u[1])
        bytes32[8] memory Q1 = map_fp2_to_g2(u[1]);
        // 4. R = Q0 + Q1              # Point addition
        bytes32[8] memory R = add_g2(Q0, Q1);
        // 5. P = clear_cofactor(R)
        // Not needed as map fp to g1 already does it
        // 6. return P
        G2_point memory P = G2_point({
            x: bytes.concat(R[0], R[1]),
            x_I: bytes.concat(R[2], R[3]),
            y: bytes.concat(R[4], R[5]),
            y_I: bytes.concat(R[6], R[7])
        });

        return P;
    }

    // adds two G1 points using the precompile
    function add_g1(
        bytes32[4] memory point1,
        bytes32[4] memory point2
    ) internal view returns (bytes32[4] memory) {
        bytes32[8] memory input;
        input[0] = point1[0];
        input[1] = point1[1];
        input[2] = point1[2];
        input[3] = point1[3];
        input[4] = point2[0];
        input[5] = point2[1];
        input[6] = point2[2];
        input[7] = point2[3];

        bytes32[4] memory result;

        // //    ABI for G1 addition precompile
        // // G1 addition call expects 256 bytes as an input that is interpreted as byte concatenation of two G1 points (128 bytes each). Output is an encoding of addition operation result - single G1 point (128 bytes).
        assembly {
            let success := staticcall(
                100000, /// gas should be 600
                0x0a, // address of BLS12_G1ADD
                input, //input offset
                256, // input size
                result, // output offset
                128 // output size
            )
            switch success
            case 0 {
                invalid()
            } //fail where we haven't enough gas to make the call
        }

        return result;
    }

    // adds two G2 points using the precompile
    function add_g2(
        bytes32[8] memory point1,
        bytes32[8] memory point2
    ) internal view returns (bytes32[8] memory) {
        bytes32[16] memory input;

        input[0] = point1[0];
        input[1] = point1[1];
        input[2] = point1[2];
        input[3] = point1[3];
        input[4] = point1[4];
        input[5] = point1[5];
        input[6] = point1[6];
        input[7] = point1[7];

        input[8] = point2[0];
        input[9] = point2[1];
        input[10] = point2[2];
        input[11] = point2[3];
        input[12] = point2[4];
        input[13] = point2[5];
        input[14] = point2[6];
        input[15] = point2[7];

        bytes32[8] memory result;

        // ABI for G2 addition precompile
        // G2 addition call expects 512 bytes as an input that is interpreted as byte concatenation of two G2 points (256 bytes each). Output is an encoding of addition operation result - single G2 point (256 bytes).
        assembly {
            let success := staticcall(
                100000, /// gas should be 4500
                0x0d, // address of BLS12_G2ADD
                input, //input offset
                512, // input size
                result, // output offset
                256 // output size
            )
            switch success
            case 0 {
                invalid()
            } //fail where we haven't enough gas to make the call
        }

        return result;
    }

    // maps a field point to a G1 point using the precompile
    function map_fp_to_g1(
        bytes memory fp
    ) internal view returns (bytes32[4] memory) {
        bytes32 a;
        bytes32 b;
        assembly {
            a := mload(add(fp, 0x20))
            b := mload(add(fp, 0x40))
        }
        bytes32[2] memory input;
        input[0] = a;
        input[1] = b;

        bytes32[4] memory result;

        // ABI for mapping Fp element to G1 point precompile
        // Field-to-curve call expects 64 bytes an an input that is interpreted as a an element of the base field. Output of this call is 128 bytes and is G1 point following respective encoding rules.
        assembly {
            let success := staticcall(
                100000, /// gas should be 5500
                0x11, // address of BLS12_MAP_FP_TO_G1
                input, //input offset
                64, // input size
                result, // output offset
                128 // output size
            )
            switch success
            case 0 {
                invalid()
            } //fail where we haven't enough gas to make the call
        }

        return result;
    }

    // maps a field point 2 to a G2 point using the precompile
    function map_fp2_to_g2(
        Field_point_2 memory fp2
    ) internal view returns (bytes32[8] memory) {
        bytes memory fp = bytes.concat(fp2.u, fp2.u_I);

        bytes32 a;
        bytes32 b;
        bytes32 c;
        bytes32 d;
        assembly {
            a := mload(add(fp, 0x20))
            b := mload(add(fp, 0x40))
            c := mload(add(fp, 0x60))
            d := mload(add(fp, 0x80))
        }

        bytes32[4] memory input;
        input[0] = a;
        input[1] = b;
        input[2] = c;
        input[3] = d;

        bytes32[8] memory result;

        // ABI for mapping Fp2 element to G2 point precompile
        // Field-to-curve call expects 128 bytes an an input that is interpreted as a an element of the quadratic extension field. Output of this call is 256 bytes and is G2 point following respective encoding rules.
        assembly {
            let success := staticcall(
                200000, /// gas should be 110000
                0x12, // address of BLS12_MAP_FP2_TO_G2
                input, //input offset
                128, // input size
                result, // output offset
                256 // output size
            )
            switch success
            case 0 {
                invalid()
            } //fail where we haven't enough gas to make the call
        }

        return result;
    }

    // https://datatracker.ietf.org/doc/html/rfc9380#section-5.2
    // Input:
    // - msg, a byte string containing the message to hash.
    // - count, the number of elements of F to output.
    // count is always 2 for curve to hash usage
    // - DST, a domain separation tag (see Section 3.1).
    function hash_to_field_fp2(
        bytes calldata message,
        bytes calldata dst
    ) public view returns (Field_point_2[2] memory) {
        // 1. len_in_bytes = count * m * L
        // so always 2 * 2 * 64 = 256
        uint16 len_in_bytes = 256;
        // 2. uniform_bytes = expand_message(msg, DST, len_in_bytes)
        bytes32[] memory pseudo_random_bytes = expand_msg_xmd(
            message,
            dst,
            len_in_bytes
        );
        Field_point_2[2] memory u;
        // No loop here saves 800 gas hardcoding offset an additional 300
        // 3. for i in (0, ..., count - 1):
        // 4.   for j in (0, ..., m - 1):
        // 5.     elm_offset = L * (j + i * m)
        // 6.     tv = substr(uniform_bytes, elm_offset, HTF_L)
        // uint8 HTF_L = 64;
        // bytes memory tv = new bytes(64);
        // 7.     e_j = OS2IP(tv) mod p
        // 8.   u_i = (e_0, ..., e_(m - 1))
        // tv = bytes.concat(pseudo_random_bytes[0], pseudo_random_bytes[1]);
        u[0].u = _modfield(pseudo_random_bytes[0], pseudo_random_bytes[1]);
        u[0].u_I = _modfield(pseudo_random_bytes[2], pseudo_random_bytes[3]);
        u[1].u = _modfield(pseudo_random_bytes[4], pseudo_random_bytes[5]);
        u[1].u_I = _modfield(pseudo_random_bytes[6], pseudo_random_bytes[7]);
        // 9. return (u_0, ..., u_(count - 1))
        return u;
    }

    // Input:
    // - msg, a byte string containing the message to hash.
    // - count, the number of elements of F to output.
    // count is always 2 for hash to curve usage
    // - DST, a domain separation tag (see Section 3.1).
    function hash_to_field_fp(
        bytes calldata message,
        bytes calldata dst
    ) public view returns (Field_point[2] memory) {
        // len_in_bytes = count * m * HTF_L
        // so always 2 * 1 * 64 = 128
        uint16 len_in_bytes = 128;

        bytes32[] memory pseudo_random_bytes = expand_msg_xmd(
            message,
            dst,
            len_in_bytes
        );
        Field_point[2] memory u;

        // No loop here saves 800 gas
        // uint8 HTF_L = 64;
        // bytes memory tv = new bytes(64);
        // uint256 elm_offset = 0 * 2;
        // tv = bytes.concat(pseudo_random_bytes[0], pseudo_random_bytes[1]);
        u[0].u = _modfield(pseudo_random_bytes[0], pseudo_random_bytes[1]);

        // uint256 elm_offset2 = 1 * 2;
        // tv = bytes.concat(pseudo_random_bytes[2], pseudo_random_bytes[3]);
        u[1].u = _modfield(pseudo_random_bytes[2], pseudo_random_bytes[3]);

        return u;
    }

    // https://datatracker.ietf.org/doc/html/rfc9380#section-5.2
    // Input:
    // - msg, a byte string.
    // - DST, a byte string of at most 255 bytes.
    // - len_in_bytes, the length of the requested output in bytes,
    //   not greater than the lesser of (255 * b_in_bytes) or 2^16-1.
    // returns bytes32[] because len_in_bytes is always a multiple of 32 in our case even 128
    function expand_msg_xmd(
        bytes calldata message,
        bytes calldata dst,
        uint16 len_in_bytes
    ) public pure returns (bytes32[] memory) {
        // 1.  ell = ceil(len_in_bytes / b_in_bytes)
        // b_in_bytes seems to be 32 for sha256
        // ceil the division
        uint ell = (len_in_bytes - 1) / 32 + 1;

        // 2.  ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
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

        bytes32 b_0;
        bytes32[] memory b = new bytes32[](ell);

        // 7.  b_0 = H(msg_prime)
        b_0 = sha256(msg_prime);

        // 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        b[0] = sha256(bytes.concat(b_0, hex"01", dst_prime));

        // 9.  for i in (2, ..., ell):
        for (uint8 i = 2; i <= ell; i++) {
            // 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
            bytes memory tmp = abi.encodePacked(b_0 ^ b[i - 2], i, dst_prime);
            b[i - 1] = sha256(tmp);
        }
        // 11. uniform_bytes = b_1 || ... || b_ell
        // 12. return substr(uniform_bytes, 0, len_in_bytes)
        // Here we don't need the uniform_bytes because b is already properly formed
        return b;
    }

    // Originaly from https://github.com/firoorg/solidity-BigNumber/blob/master/src/BigNumbers.sol

    /** @notice Modular Exponentiation: Takes bytes values for base, exp, mod and calls precompile for (base^exp)%^mod
     * @dev modexp: Wrapper for built-in modexp (contract 0x5) as described here:
     *              https://github.com/ethereum/EIPs/pull/198
     *
     * @param _b1 bytes32 base first 32 bytes
     * @param _b2 bytes32 base last 32 bytes
     * @param r bytes result.
     */
    // passing two bytes32 instead of bytes memory saves approx 700 gas per call
    function _modfield(
        bytes32 _b1,
        bytes32 _b2
    ) internal view returns (bytes memory r) {
        assembly {
            let bl := 0x40
            let ml := 0x40

            let freemem := mload(0x40) // Free memory pointer is always stored at 0x40

            // arg[0] = base.length @ +0
            mstore(freemem, bl)
            // arg[1] = exp.length @ +32
            mstore(add(freemem, 0x20), 0x20)
            // arg[2] = mod.length @ +64
            mstore(add(freemem, 0x40), ml)

            // arg[3] = base.bits @ + 96
            // places the first 32 bytes of _b1 and the last 32 bytes of _b2
            mstore(add(freemem, 0x60), _b1)
            mstore(add(freemem, 0x80), _b2)

            let size := add(0x60, bl)
            // arg[4] = exp.bits @ +96+base.length
            // exponent always 1
            mstore(add(freemem, size), 1)

            size := add(size, 0x20)

            // arg[5] = mod.bits @ +96+base.length+exp.length
            // this field_modulus as hex 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
            // we add the 0 prefix so that the result will be exactly 64 bytes
            // saves 300 gas per call instead of sending it along every time
            // places the first 32 bytes and the last 32 bytes of the field modulus
            mstore(
                add(freemem, size),
                0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7
            )
            mstore(
                add(freemem, add(size, 0x20)),
                0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
            )

            // Total size of input = 96+base.length+exp.length+mod.length
            size := add(size, ml)
            // Invoke contract 0x5, put return value right after mod.length, @ +96
            let success := staticcall(
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

            r := sub(msword_ptr, 0x20)
            mstore(r, length)

            // point to the location of the return value (length, bits)
            //assuming mod length is multiple of 32, return value is already in the right format.
            mstore(0x40, add(add(0x60, freemem), ml)) //deallocate freemem pointer
        }
    }
}
