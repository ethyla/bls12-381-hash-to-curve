// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Hash_to_curve} from "../src/Hash_to_curve.sol";

contract Hash_to_curveTest is Test {
    bytes expand_msg_DST = "QUUX-V01-CS02-with-expander-SHA256-128";

    Hash_to_curve public hasher;

    function setUp() public {
        hasher = new Hash_to_curve();
    }

    //test cases from:
    //https://datatracker.ietf.org/doc/html/rfc9380#name-expand_message_xmdsha-256
    function test_expand_msg_xmd_empty_msg_0x20() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "",
            expand_msg_DST,
            0x20
        );
        bytes
            memory expected = hex"68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235";

        assertEq(bytes.concat(result[0]), expected);
    }

    function test_expand_msg_xmd_abc_0x20() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "abc",
            expand_msg_DST,
            0x20
        );
        bytes
            memory expected = hex"d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615";

        assertEq(bytes.concat(result[0]), expected);
    }

    function test_expand_msg_xmd_abcdef0123456789_0x20() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "abcdef0123456789",
            expand_msg_DST,
            0x20
        );
        bytes
            memory expected = hex"eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1";

        assertEq(bytes.concat(result[0]), expected);
    }

    function test_expand_msg_xmd_q128_0x20() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            expand_msg_DST,
            0x20
        );
        bytes
            memory expected = hex"b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9";

        assertEq(bytes.concat(result[0]), expected);
    }

    function test_expand_msg_xmd_a512_0x20() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            expand_msg_DST,
            0x20
        );
        bytes
            memory expected = hex"4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c";

        assertEq(bytes.concat(result[0]), expected);
    }

    function test_expand_msg_xmd_empty_msg_0x80() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "",
            expand_msg_DST,
            0x80
        );
        bytes
            memory expected = hex"af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced";

        assertEq(
            bytes.concat(result[0], result[1], result[2], result[3]),
            expected
        );
    }

    function test_expand_msg_xmd_abc_0x80() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "abc",
            expand_msg_DST,
            0x80
        );
        bytes
            memory expected = hex"abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40";

        assertEq(
            bytes.concat(result[0], result[1], result[2], result[3]),
            expected
        );
    }

    function test_expand_msg_xmd_abcdef0123456789_0x80() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "abcdef0123456789",
            expand_msg_DST,
            0x80
        );
        bytes
            memory expected = hex"ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df";

        assertEq(
            bytes.concat(result[0], result[1], result[2], result[3]),
            expected
        );
    }

    function test_expand_msg_xmd_q128_0x80() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            expand_msg_DST,
            0x80
        );
        bytes
            memory expected = hex"80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a";

        assertEq(
            bytes.concat(result[0], result[1], result[2], result[3]),
            expected
        );
    }

    function test_expand_msg_xmd_a512_0x80() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            expand_msg_DST,
            0x80
        );
        bytes
            memory expected = hex"546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d06d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487";

        assertEq(
            bytes.concat(result[0], result[1], result[2], result[3]),
            expected
        );
    }
}
