// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Hash_to_curve} from "../src/Hash_to_curve.sol";

contract Hash_to_curveTest is Test {
    Hash_to_curve public hasher;
    bytes DST = "QUUX-V01-CS02-with-expander";

    function setUp() public {
        hasher = new Hash_to_curve();
    }

    // test cases from https://github.com/ethereum/py_ecc/blob/main/tests/bls/test_expand_message_xmd.py
    function test_expand_msg_xmd() public view {
        bytes memory result = hasher.expand_msg_xmd("", 0x20, DST);
        bytes
            memory expected = hex"f659819a6473c1835b25ea59e3d38914c98b374f0970b7e4c92181df928fca88";
        assertEq(result, expected);
    }

    function test_expand_msg_abc_0x20() public view {
        bytes memory result = hasher.expand_msg_xmd("abc", 0x20, DST);
        bytes
            memory expected = hex"1c38f7c211ef233367b2420d04798fa4698080a8901021a795a1151775fe4da7";
        assertEq(result, expected);
    }

    function test_expand_msg_abcdef0123456789_0x20() public view {
        bytes memory result = hasher.expand_msg_xmd(
            "abcdef0123456789",
            0x20,
            DST
        );
        bytes
            memory expected = hex"8f7e7b66791f0da0dbb5ec7c22ec637f79758c0a48170bfb7c4611bd304ece89";
        assertEq(result, expected);
    }

    function test_expand_msg_q128_0x20() public view {
        bytes memory result = hasher.expand_msg_xmd(
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            0x20,
            DST
        );
        bytes
            memory expected = hex"72d5aa5ec810370d1f0013c0df2f1d65699494ee2a39f72e1716b1b964e1c642";
        assertEq(result, expected);
    }

    function test_expand_msg_a512_0x20() public view {
        bytes memory result = hasher.expand_msg_xmd(
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            0x20,
            DST
        );
        bytes
            memory expected = hex"3b8e704fc48336aca4c2a12195b720882f2162a4b7b13a9c350db46f429b771b";
        assertEq(result, expected);
    }

    function test_expand_msg_empty_0x80() public view {
        bytes memory result = hasher.expand_msg_xmd("", 0x80, DST);
        bytes
            memory expected = hex"8bcffd1a3cae24cf9cd7ab85628fd111bb17e3739d3b53f89580d217aa79526f1708354a76a402d3569d6a9d19ef3de4d0b991e4f54b9f20dcde9b95a66824cbdf6c1a963a1913d43fd7ac443a02fc5d9d8d77e2071b86ab114a9f34150954a7531da568a1ea8c760861c0cde2005afc2c114042ee7b5848f5303f0611cf297f";
        assertEq(result, expected);
    }

    function test_expand_msg_abc_0x80() public view {
        bytes memory result = hasher.expand_msg_xmd("abc", 0x80, DST);
        bytes
            memory expected = hex"fe994ec51bdaa821598047b3121c149b364b178606d5e72bfbb713933acc29c186f316baecf7ea22212f2496ef3f785a27e84a40d8b299cec56032763eceeff4c61bd1fe65ed81decafff4a31d0198619c0aa0c6c51fca15520789925e813dcfd318b542f8799441271f4db9ee3b8092a7a2e8d5b75b73e28fb1ab6b4573c192";
        assertEq(result, expected);
    }

    function test_expand_msg_abcdef0123456789_0x80() public view {
        bytes memory result = hasher.expand_msg_xmd(
            "abcdef0123456789",
            0x80,
            DST
        );
        bytes
            memory expected = hex"c9ec7941811b1e19ce98e21db28d22259354d4d0643e301175e2f474e030d32694e9dd5520dde93f3600d8edad94e5c364903088a7228cc9eff685d7eaac50d5a5a8229d083b51de4ccc3733917f4b9535a819b445814890b7029b5de805bf62b33a4dc7e24acdf2c924e9fe50d55a6b832c8c84c7f82474b34e48c6d43867be";
        assertEq(result, expected);
    }

    function test_expand_msg_q128_0x80() public view {
        bytes memory result = hasher.expand_msg_xmd(
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            0x80,
            DST
        );
        bytes
            memory expected = hex"48e256ddba722053ba462b2b93351fc966026e6d6db493189798181c5f3feea377b5a6f1d8368d7453faef715f9aecb078cd402cbd548c0e179c4ed1e4c7e5b048e0a39d31817b5b24f50db58bb3720fe96ba53db947842120a068816ac05c159bb5266c63658b4f000cbf87b1209a225def8ef1dca917bcda79a1e42acd8069";
        assertEq(result, expected);
    }

    function test_expand_msg_a512_0x80() public view {
        bytes memory result = hasher.expand_msg_xmd(
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            0x80,
            DST
        );
        bytes
            memory expected = hex"396962db47f749ec3b5042ce2452b619607f27fd3939ece2746a7614fb83a1d097f554df3927b084e55de92c7871430d6b95c2a13896d8a33bc48587b1f66d21b128a1a8240d5b0c26dfe795a1a842a0807bb148b77c2ef82ed4b6c9f7fcb732e7f94466c8b51e52bf378fba044a31f5cb44583a892f5969dcd73b3fa128816e";
        assertEq(result, expected);
    }

    function test_hash_to_field_fq2() public view {
        bytes[][] memory result = hasher.hash_to_field_fq2("", 1, DST);
        bytes
            memory expected1 = hex"16da1e6feccd22e6c66989dacceb151ff125450611b39ea5ca765cda844710d51af4dc626861306a3eccf92145b5d47b";
        bytes
            memory expected2 = hex"11ff784ffcc1f8a96dc093531449285022df656d2bc377c29ccbf7029aac742c0fead154443b8a07062a6a8f1da0fe9d";
        console.logBytes(result[0][0]);
        console.logBytes(result[0][1]);
        console.logBytes(result[1][0]);
        console.logBytes(result[1][1]);

        assertEq(result[0][0], expected1);
        assertEq(result[0][1], expected2);
    }
}
