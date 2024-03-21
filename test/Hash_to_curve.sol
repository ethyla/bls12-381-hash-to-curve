// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Hash_to_curve} from "../src/Hash_to_curve.sol";

contract Hash_to_curveTest is Test {
    bytes expand_msg_DST = "QUUX-V01-CS02-with-expander-SHA256-128";
    bytes hash_to_G2_DST = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
    bytes hash_to_G1_DST = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

    Hash_to_curve public hasher;

    function setUp() public {
        hasher = new Hash_to_curve();
    }

    //test cases from:
    //https://datatracker.ietf.org/doc/html/rfc9380#name-expand_message_xmdsha-256
    function test_expand_msg_xmd_empty_msg_0x20() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "",
            0x20,
            expand_msg_DST
        );
        bytes
            memory expected = hex"68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235";

        assertEq(bytes.concat(result[0]), expected);
    }

    function test_expand_msg_xmd_abc_0x20() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "abc",
            0x20,
            expand_msg_DST
        );
        bytes
            memory expected = hex"d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615";

        assertEq(bytes.concat(result[0]), expected);
    }

    function test_expand_msg_xmd_abcdef0123456789_0x20() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "abcdef0123456789",
            0x20,
            expand_msg_DST
        );
        bytes
            memory expected = hex"eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1";

        assertEq(bytes.concat(result[0]), expected);
    }

    function test_expand_msg_xmd_q128_0x20() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            0x20,
            expand_msg_DST
        );
        bytes
            memory expected = hex"b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9";

        assertEq(bytes.concat(result[0]), expected);
    }

    function test_expand_msg_xmd_a512_0x20() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            0x20,
            expand_msg_DST
        );
        bytes
            memory expected = hex"4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c";

        assertEq(bytes.concat(result[0]), expected);
    }

    function test_expand_msg_xmd_empty_msg_0x80() public view {
        bytes32[] memory result = hasher.expand_msg_xmd(
            "",
            0x80,
            expand_msg_DST
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
            0x80,
            expand_msg_DST
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
            0x80,
            expand_msg_DST
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
            0x80,
            expand_msg_DST
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
            0x80,
            expand_msg_DST
        );
        bytes
            memory expected = hex"546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d06d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487";

        assertEq(
            bytes.concat(result[0], result[1], result[2], result[3]),
            expected
        );
    }

    function test_hash_to_field_fp2_empty_msg() public view {
        bytes[2][2] memory result = hasher.hash_to_field_fp2(
            "",
            hash_to_G2_DST
        );
        bytes
            memory expected_u0 = hex"03dbc2cce174e91ba93cbb08f26b917f98194a2ea08d1cce75b2b9cc9f21689d80bd79b594a613d0a68eb807dfdc1cf8";
        bytes
            memory expected_u0_I = hex"05a2acec64114845711a54199ea339abd125ba38253b70a92c876df10598bd1986b739cad67961eb94f7076511b3b39a";
        bytes
            memory expected_u1 = hex"02f99798e8a5acdeed60d7e18e9120521ba1f47ec090984662846bc825de191b5b7641148c0dbc237726a334473eee94";
        bytes
            memory expected_u1_I = hex"145a81e418d4010cc027a68f14391b30074e89e60ee7a22f87217b2f6eb0c4b94c9115b436e6fa4607e95a98de30a435";

        assertEq(result[0][0], expected_u0);
        assertEq(result[0][1], expected_u0_I);
        assertEq(result[1][0], expected_u1);
        assertEq(result[1][1], expected_u1_I);
    }

    function test_hash_to_field_fp2_msg_abc() public view {
        bytes[2][2] memory result = hasher.hash_to_field_fp2(
            "abc",
            hash_to_G2_DST
        );
        bytes
            memory expected_u0 = hex"15f7c0aa8f6b296ab5ff9c2c7581ade64f4ee6f1bf18f55179ff44a2cf355fa53dd2a2158c5ecb17d7c52f63e7195771";
        bytes
            memory expected_u0_I = hex"01c8067bf4c0ba709aa8b9abc3d1cef589a4758e09ef53732d670fd8739a7274e111ba2fcaa71b3d33df2a3a0c8529dd";
        bytes
            memory expected_u1 = hex"187111d5e088b6b9acfdfad078c4dacf72dcd17ca17c82be35e79f8c372a693f60a033b461d81b025864a0ad051a06e4";
        bytes
            memory expected_u1_I = hex"08b852331c96ed983e497ebc6dee9b75e373d923b729194af8e72a051ea586f3538a6ebb1e80881a082fa2b24df9f566";

        assertEq(result[0][0], expected_u0);
        assertEq(result[0][1], expected_u0_I);
        assertEq(result[1][0], expected_u1);
        assertEq(result[1][1], expected_u1_I);
    }

    function test_hash_to_field_msg_fp2_abcdef0123456789() public view {
        bytes[2][2] memory result = hasher.hash_to_field_fp2(
            "abcdef0123456789",
            hash_to_G2_DST
        );
        bytes
            memory expected_u0 = hex"0313d9325081b415bfd4e5364efaef392ecf69b087496973b229303e1816d2080971470f7da112c4eb43053130b785e1";
        bytes
            memory expected_u0_I = hex"062f84cb21ed89406890c051a0e8b9cf6c575cf6e8e18ecf63ba86826b0ae02548d83b483b79e48512b82a6c0686df8f";
        bytes
            memory expected_u1 = hex"1739123845406baa7be5c5dc74492051b6d42504de008c635f3535bb831d478a341420e67dcc7b46b2e8cba5379cca97";
        bytes
            memory expected_u1_I = hex"01897665d9cb5db16a27657760bbea7951f67ad68f8d55f7113f24ba6ddd82caef240a9bfa627972279974894701d975";

        assertEq(result[0][0], expected_u0);
        assertEq(result[0][1], expected_u0_I);
        assertEq(result[1][0], expected_u1);
        assertEq(result[1][1], expected_u1_I);
    }

    function test_hash_to_field_fp2_msg_q128() public view {
        bytes[2][2] memory result = hasher.hash_to_field_fp2(
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            hash_to_G2_DST
        );
        bytes
            memory expected_u0 = hex"025820cefc7d06fd38de7d8e370e0da8a52498be9b53cba9927b2ef5c6de1e12e12f188bbc7bc923864883c57e49e253";
        bytes
            memory expected_u0_I = hex"034147b77ce337a52e5948f66db0bab47a8d038e712123bb381899b6ab5ad20f02805601e6104c29df18c254b8618c7b";
        bytes
            memory expected_u1 = hex"0930315cae1f9a6017c3f0c8f2314baa130e1cf13f6532bff0a8a1790cd70af918088c3db94bda214e896e1543629795";
        bytes
            memory expected_u1_I = hex"10c4df2cacf67ea3cb3108b00d4cbd0b3968031ebc8eac4b1ebcefe84d6b715fde66bef0219951ece29d1facc8a520ef";

        assertEq(result[0][0], expected_u0);
        assertEq(result[0][1], expected_u0_I);
        assertEq(result[1][0], expected_u1);
        assertEq(result[1][1], expected_u1_I);
    }

    function test_hash_to_field_fp2_msg_a512() public view {
        bytes[2][2] memory result = hasher.hash_to_field_fp2(
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            hash_to_G2_DST
        );
        bytes
            memory expected_u0 = hex"190b513da3e66fc9a3587b78c76d1d132b1152174d0b83e3c1114066392579a45824c5fa17649ab89299ddd4bda54935";
        bytes
            memory expected_u0_I = hex"12ab625b0fe0ebd1367fe9fac57bb1168891846039b4216b9d94007b674de2d79126870e88aeef54b2ec717a887dcf39";
        bytes
            memory expected_u1 = hex"0e6a42010cf435fb5bacc156a585e1ea3294cc81d0ceb81924d95040298380b164f702275892cedd81b62de3aba3f6b5";
        bytes
            memory expected_u1_I = hex"117d9a0defc57a33ed208428cb84e54c85a6840e7648480ae428838989d25d97a0af8e3255be62b25c2a85630d2dddd8";

        assertEq(result[0][0], expected_u0);
        assertEq(result[0][1], expected_u0_I);
        assertEq(result[1][0], expected_u1);
        assertEq(result[1][1], expected_u1_I);
    }

    function test_hash_to_field_fp_empty_msg() public view {
        bytes[2] memory result = hasher.hash_to_field_fp("", hash_to_G1_DST);
        bytes
            memory expected_u0 = hex"0ba14bd907ad64a016293ee7c2d276b8eae71f25a4b941eece7b0d89f17f75cb3ae5438a614fb61d6835ad59f29c564f";
        bytes
            memory expected_u1 = hex"019b9bd7979f12657976de2884c7cce192b82c177c80e0ec604436a7f538d231552f0d96d9f7babe5fa3b19b3ff25ac9";

        assertEq(result[0], expected_u0);
        assertEq(result[1], expected_u1);
    }

    function test_hash_to_field_fp_msg_abc() public view {
        bytes[2] memory result = hasher.hash_to_field_fp("abc", hash_to_G1_DST);
        bytes
            memory expected_u0 = hex"0d921c33f2bad966478a03ca35d05719bdf92d347557ea166e5bba579eea9b83e9afa5c088573c2281410369fbd32951";
        bytes
            memory expected_u1 = hex"003574a00b109ada2f26a37a91f9d1e740dffd8d69ec0c35e1e9f4652c7dba61123e9dd2e76c655d956e2b3462611139";

        assertEq(result[0], expected_u0);
        assertEq(result[1], expected_u1);
    }

    function test_hash_to_field_fp_msg_abcdef0123456789() public view {
        bytes[2] memory result = hasher.hash_to_field_fp(
            "abcdef0123456789",
            hash_to_G1_DST
        );
        bytes
            memory expected_u0 = hex"062d1865eb80ebfa73dcfc45db1ad4266b9f3a93219976a3790ab8d52d3e5f1e62f3b01795e36834b17b70e7b76246d4";
        bytes
            memory expected_u1 = hex"0cdc3e2f271f29c4ff75020857ce6c5d36008c9b48385ea2f2bf6f96f428a3deb798aa033cd482d1cdc8b30178b08e3a";

        assertEq(result[0], expected_u0);
        assertEq(result[1], expected_u1);
    }

    function test_hash_to_field_fp_msg_q128() public view {
        bytes[2] memory result = hasher.hash_to_field_fp(
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            hash_to_G1_DST
        );
        bytes
            memory expected_u0 = hex"010476f6a060453c0b1ad0b628f3e57c23039ee16eea5e71bb87c3b5419b1255dc0e5883322e563b84a29543823c0e86";
        bytes
            memory expected_u1 = hex"0b1a912064fb0554b180e07af7e787f1f883a0470759c03c1b6509eb8ce980d1670305ae7b928226bb58fdc0a419f46e";

        assertEq(result[0], expected_u0);
        assertEq(result[1], expected_u1);
    }

    function test_hash_to_field_fp_msg_a512() public view {
        bytes[2] memory result = hasher.hash_to_field_fp(
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            hash_to_G1_DST
        );
        bytes
            memory expected_u0 = hex"0a8ffa7447f6be1c5a2ea4b959c9454b431e29ccc0802bc052413a9c5b4f9aac67a93431bd480d15be1e057c8a08e8c6";
        bytes
            memory expected_u1 = hex"05d487032f602c90fa7625dbafe0f4a49ef4a6b0b33d7bb349ff4cf5410d297fd6241876e3e77b651cfc8191e40a68b7";

        assertEq(result[0], expected_u0);
        assertEq(result[1], expected_u1);
    }

    function test_hash_to_curve_g1_empty_msg() public view {
        bytes[2] memory result = hasher.hash_to_curve_g1("");
        bytes
            memory expected_P_x = hex"052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1";
        bytes
            memory expected_P_y = hex"08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265";

        assertEq(result[0], expected_P_x);
        assertEq(result[1], expected_P_y);
    }

    function test_hash_to_curve_g1_msg_abc() public view {
        bytes[2] memory result = hasher.hash_to_curve_g1("abc");
        bytes
            memory expected_P_x = hex"03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903";
        bytes
            memory expected_P_y = hex"0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d";

        assertEq(result[0], expected_P_x);
        assertEq(result[1], expected_P_y);
    }

    function test_hash_to_curve_g1_msg_abcdef0123456789() public view {
        bytes[2] memory result = hasher.hash_to_curve_g1("abcdef0123456789");
        bytes
            memory expected_P_x = hex"11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98";
        bytes
            memory expected_P_y = hex"03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709";

        assertEq(result[0], expected_P_x);
        assertEq(result[1], expected_P_y);
    }

    function test_hash_to_curve_g1_msg_q128() public view {
        bytes[2] memory result = hasher.hash_to_curve_g1(
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
        );
        bytes
            memory expected_P_x = hex"15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488";
        bytes
            memory expected_P_y = hex"1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38";

        assertEq(result[0], expected_P_x);
        assertEq(result[1], expected_P_y);
    }

    function test_hash_to_curve_g1_msg_a512() public view {
        bytes[2] memory result = hasher.hash_to_curve_g1(
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        bytes
            memory expected_P_x = hex"082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe";
        bytes
            memory expected_P_y = hex"05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8";

        assertEq(result[0], expected_P_x);
        assertEq(result[1], expected_P_y);
    }

    function test_hash_to_curve_g2_empty_msg() public view {
        bytes[4] memory result = hasher.hash_to_curve_g2("");
        bytes
            memory expected_P_x = hex"0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a";
        bytes
            memory expected_P_x_I = hex"05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d";
        bytes
            memory expected_P_y = hex"0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92";
        bytes
            memory expected_P_y_I = hex"12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6";

        assertEq(result[0], expected_P_x);
        assertEq(result[1], expected_P_x_I);
        assertEq(result[2], expected_P_y);
        assertEq(result[3], expected_P_y_I);
    }

    function test_hash_to_curve_g2_msg_abc() public view {
        bytes[4] memory result = hasher.hash_to_curve_g2("abc");
        bytes
            memory expected_P_x = hex"02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6";
        bytes
            memory expected_P_x_I = hex"139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8";
        bytes
            memory expected_P_y = hex"1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48";
        bytes
            memory expected_P_y_I = hex"00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16";

        assertEq(result[0], expected_P_x);
        assertEq(result[1], expected_P_x_I);
        assertEq(result[2], expected_P_y);
        assertEq(result[3], expected_P_y_I);
    }

    function test_hash_to_curve_g2_msg_abcdef0123456789() public view {
        bytes[4] memory result = hasher.hash_to_curve_g2("abcdef0123456789");
        bytes
            memory expected_P_x = hex"121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0";
        bytes
            memory expected_P_x_I = hex"190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c";
        bytes
            memory expected_P_y = hex"05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8";
        bytes
            memory expected_P_y_I = hex"0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be";

        assertEq(result[0], expected_P_x);
        assertEq(result[1], expected_P_x_I);
        assertEq(result[2], expected_P_y);
        assertEq(result[3], expected_P_y_I);
    }

    function test_hash_to_curve_g2_msg_q128() public view {
        bytes[4] memory result = hasher.hash_to_curve_g2(
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
        );
        bytes
            memory expected_P_x = hex"19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da";
        bytes
            memory expected_P_x_I = hex"0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb91";
        bytes
            memory expected_P_y = hex"14f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192";
        bytes
            memory expected_P_y_I = hex"09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e5662";

        assertEq(result[0], expected_P_x);
        assertEq(result[1], expected_P_x_I);
        assertEq(result[2], expected_P_y);
        assertEq(result[3], expected_P_y_I);
    }

    function test_hash_to_curve_g2_msg_a512() public view {
        bytes[4] memory result = hasher.hash_to_curve_g2(
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        bytes
            memory expected_P_x = hex"01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534";
        bytes
            memory expected_P_x_I = hex"11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569";
        bytes
            memory expected_P_y = hex"0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e";
        bytes
            memory expected_P_y_I = hex"03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52";

        assertEq(result[0], expected_P_x);
        assertEq(result[1], expected_P_x_I);
        assertEq(result[2], expected_P_y);
        assertEq(result[3], expected_P_y_I);
    }
}
