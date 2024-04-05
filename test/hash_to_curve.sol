// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Hash_to_curve, G1_point, G2_point} from "../src/Hash_to_curve.sol";

contract Hash_to_curve_Test is Test {
    bytes expand_msg_DST = "QUUX-V01-CS02-with-expander-SHA256-128";
    bytes hash_to_G2_DST = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
    bytes hash_to_G1_DST = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

    Hash_to_curve public hasher;

    function setUp() public {
        hasher = new Hash_to_curve();
    }

    //test cases from:
    //https://datatracker.ietf.org/doc/html/rfc9380#name-bls12381g1_xmdsha-256_sswu_
    //https://datatracker.ietf.org/doc/html/rfc9380#name-bls12381g2_xmdsha-256_sswu_
    function test_hash_to_curve_g1_empty_msg() public view {
        G1_point memory result = hasher.hash_to_curve_g1("", hash_to_G1_DST);
        bytes
            memory expected_P_x = hex"052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1";
        bytes
            memory expected_P_y = hex"08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265";

        assertEq(result.x, expected_P_x);
        assertEq(result.y, expected_P_y);
    }

    function test_hash_to_curve_g1_msg_abc() public view {
        G1_point memory result = hasher.hash_to_curve_g1("abc", hash_to_G1_DST);
        bytes
            memory expected_P_x = hex"03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903";
        bytes
            memory expected_P_y = hex"0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d";

        assertEq(result.x, expected_P_x);
        assertEq(result.y, expected_P_y);
    }

    function test_hash_to_curve_g1_msg_abcdef0123456789() public view {
        G1_point memory result = hasher.hash_to_curve_g1(
            "abcdef0123456789",
            hash_to_G1_DST
        );
        bytes
            memory expected_P_x = hex"0000000000000000000000000000000011e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98";
        bytes
            memory expected_P_y = hex"0000000000000000000000000000000003a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709";

        assertEq(result.x, expected_P_x);
        assertEq(result.y, expected_P_y);
    }

    function test_hash_to_curve_g1_msg_q128() public view {
        G1_point memory result = hasher.hash_to_curve_g1(
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            hash_to_G1_DST
        );
        bytes
            memory expected_P_x = hex"15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488";
        bytes
            memory expected_P_y = hex"1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38";

        assertEq(result.x, expected_P_x);
        assertEq(result.y, expected_P_y);
    }

    function test_hash_to_curve_g1_msg_a512() public view {
        G1_point memory result = hasher.hash_to_curve_g1(
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            hash_to_G1_DST
        );
        bytes
            memory expected_P_x = hex"082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe";
        bytes
            memory expected_P_y = hex"05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8";

        assertEq(result.x, expected_P_x);
        assertEq(result.y, expected_P_y);
    }

    function test_hash_to_curve_g2_empty_msg() public view {
        G2_point memory result = hasher.hash_to_curve_g2("", hash_to_G2_DST);
        bytes
            memory expected_P_x = hex"0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a";
        bytes
            memory expected_P_x_I = hex"05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d";
        bytes
            memory expected_P_y = hex"0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92";
        bytes
            memory expected_P_y_I = hex"12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6";

        assertEq(result.x, expected_P_x);
        assertEq(result.x_I, expected_P_x_I);
        assertEq(result.y, expected_P_y);
        assertEq(result.y_I, expected_P_y_I);
    }

    function test_hash_to_curve_g2_msg_abc() public view {
        G2_point memory result = hasher.hash_to_curve_g2("abc", hash_to_G2_DST);
        bytes
            memory expected_P_x = hex"02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6";
        bytes
            memory expected_P_x_I = hex"139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8";
        bytes
            memory expected_P_y = hex"1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48";
        bytes
            memory expected_P_y_I = hex"00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16";

        assertEq(result.x, expected_P_x);
        assertEq(result.x_I, expected_P_x_I);
        assertEq(result.y, expected_P_y);
        assertEq(result.y_I, expected_P_y_I);
    }

    function test_hash_to_curve_g2_msg_abcdef0123456789() public view {
        G2_point memory result = hasher.hash_to_curve_g2(
            "abcdef0123456789",
            hash_to_G2_DST
        );
        bytes
            memory expected_P_x = hex"121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0";
        bytes
            memory expected_P_x_I = hex"190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c";
        bytes
            memory expected_P_y = hex"05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8";
        bytes
            memory expected_P_y_I = hex"0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be";

        assertEq(result.x, expected_P_x);
        assertEq(result.x_I, expected_P_x_I);
        assertEq(result.y, expected_P_y);
        assertEq(result.y_I, expected_P_y_I);
    }

    function test_hash_to_curve_g2_msg_q128() public view {
        G2_point memory result = hasher.hash_to_curve_g2(
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            hash_to_G2_DST
        );
        bytes
            memory expected_P_x = hex"19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da";
        bytes
            memory expected_P_x_I = hex"0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb91";
        bytes
            memory expected_P_y = hex"14f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192";
        bytes
            memory expected_P_y_I = hex"09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e5662";

        assertEq(result.x, expected_P_x);
        assertEq(result.x_I, expected_P_x_I);
        assertEq(result.y, expected_P_y);
        assertEq(result.y_I, expected_P_y_I);
    }

    function test_hash_to_curve_g2_msg_a512() public view {
        G2_point memory result = hasher.hash_to_curve_g2(
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            hash_to_G2_DST
        );
        bytes
            memory expected_P_x = hex"01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534";
        bytes
            memory expected_P_x_I = hex"11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569";
        bytes
            memory expected_P_y = hex"0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e";
        bytes
            memory expected_P_y_I = hex"03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52";

        assertEq(result.x, expected_P_x);
        assertEq(result.x_I, expected_P_x_I);
        assertEq(result.y, expected_P_y);
        assertEq(result.y_I, expected_P_y_I);
    }
}
