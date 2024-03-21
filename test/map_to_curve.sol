// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Hash_to_curve} from "../src/Hash_to_curve.sol";

contract Hash_to_field_Test is Test {
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
    // function test_hash_to_field_fp2_empty_msg() public view {
    //     bytes[2][2] memory result = hasher.hash_to_field_fp2(
    //         "",
    //         hash_to_G2_DST
    //     );
    //     bytes
    //         memory expected_u0 = hex"03dbc2cce174e91ba93cbb08f26b917f98194a2ea08d1cce75b2b9cc9f21689d80bd79b594a613d0a68eb807dfdc1cf8";
    //     bytes
    //         memory expected_u0_I = hex"05a2acec64114845711a54199ea339abd125ba38253b70a92c876df10598bd1986b739cad67961eb94f7076511b3b39a";
    //     bytes
    //         memory expected_u1 = hex"02f99798e8a5acdeed60d7e18e9120521ba1f47ec090984662846bc825de191b5b7641148c0dbc237726a334473eee94";
    //     bytes
    //         memory expected_u1_I = hex"145a81e418d4010cc027a68f14391b30074e89e60ee7a22f87217b2f6eb0c4b94c9115b436e6fa4607e95a98de30a435";

    //     assertEq(result[0][0], expected_u0);
    //     assertEq(result[0][1], expected_u0_I);
    //     assertEq(result[1][0], expected_u1);
    //     assertEq(result[1][1], expected_u1_I);
    // }

    // these need fixing the q are the results of the map to curve for the two field points
    // function test_hash_to_curve_g1_empty_msg() public view {
    //     bytes[4] memory result = hasher.hash_to_curve_g1("");
    //     bytes
    //         memory expected_Q0_x = hex"11a3cce7e1d90975990066b2f2643b9540fa40d6137780df4e753a8054d07580db3b7f1f03396333d4a359d1fe3766fe";
    //     bytes
    //         memory expected_Q0_y = hex"0eeaf6d794e479e270da10fdaf768db4c96b650a74518fc67b04b03927754bac66f3ac720404f339ecdcc028afa091b7";
    //     bytes
    //         memory expected_Q1_x = hex"160003aaf1632b13396dbad518effa00fff532f604de1a7fc2082ff4cb0afa2d63b2c32da1bef2bf6c5ca62dc6b72f9c";
    //     bytes
    //         memory expected_Q1_y = hex"0d8bb2d14e20cf9f6036152ed386d79189415b6d015a20133acb4e019139b94e9c146aaad5817f866c95d609a361735e";

    //     assertEq(result[0], expected_Q0_x);
    //     assertEq(result[1], expected_Q0_y);
    //     assertEq(result[2], expected_Q1_x);
    //     assertEq(result[3], expected_Q1_y);
    // }

    // function test_hash_to_curve_g1_msg_abc() public view {
    //     bytes[4] memory result = hasher.hash_to_curve_g1("abc");
    //     bytes
    //         memory expected_Q0_x = hex"125435adce8e1cbd1c803e7123f45392dc6e326d292499c2c45c5865985fd74fe8f042ecdeeec5ecac80680d04317d80";
    //     bytes
    //         memory expected_Q0_y = hex"0e8828948c989126595ee30e4f7c931cbd6f4570735624fd25aef2fa41d3f79cfb4b4ee7b7e55a8ce013af2a5ba20bf2";
    //     bytes
    //         memory expected_Q1_x = hex"11def93719829ecda3b46aa8c31fc3ac9c34b428982b898369608e4f042babee6c77ab9218aad5c87ba785481eff8ae4";
    //     bytes
    //         memory expected_Q1_y = hex"0007c9cef122ccf2efd233d6eb9bfc680aa276652b0661f4f820a653cec1db7ff69899f8e52b8e92b025a12c822a6ce6";

    //     assertEq(result[0], expected_Q0_x);
    //     assertEq(result[1], expected_Q0_y);
    //     assertEq(result[2], expected_Q1_x);
    //     assertEq(result[3], expected_Q1_y);
    // }

    // function test_hash_to_curve_g1_msg_abcdef0123456789() public view {
    //     bytes[4] memory result = hasher.hash_to_curve_g1("abcdef0123456789");
    //     bytes
    //         memory expected_Q0_x = hex"08834484878c217682f6d09a4b51444802fdba3d7f2df9903a0ddadb92130ebbfa807fffa0eabf257d7b48272410afff";
    //     bytes
    //         memory expected_Q0_y = hex"0b318f7ecf77f45a0f038e62d7098221d2dbbca2a394164e2e3fe953dc714ac2cde412d8f2d7f0c03b259e6795a2508e";
    //     bytes
    //         memory expected_Q1_x = hex"158418ed6b27e2549f05531a8281b5822b31c3bf3144277fbb977f8d6e2694fedceb7011b3c2b192f23e2a44b2bd106e";
    //     bytes
    //         memory expected_Q1_y = hex"1879074f344471fac5f839e2b4920789643c075792bec5af4282c73f7941cda5aa77b00085eb10e206171b9787c4169f";

    //     assertEq(result[0], expected_Q0_x);
    //     assertEq(result[1], expected_Q0_y);
    //     assertEq(result[2], expected_Q1_x);
    //     assertEq(result[3], expected_Q1_y);
    // }

    // function test_hash_to_curve_g1_msg_q128() public view {
    //     bytes[4] memory result = hasher.hash_to_curve_g1(
    //         "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
    //     );
    //     bytes
    //         memory expected_Q0_x = hex"0cbd7f84ad2c99643fea7a7ac8f52d63d66cefa06d9a56148e58b984b3dd25e1f41ff47154543343949c64f88d48a710";
    //     bytes
    //         memory expected_Q0_y = hex"052c00e4ed52d000d94881a5638ae9274d3efc8bc77bc0e5c650de04a000b2c334a9e80b85282a00f3148dfdface0865";
    //     bytes
    //         memory expected_Q1_x = hex"06493fb68f0d513af08be0372f849436a787e7b701ae31cb964d968021d6ba6bd7d26a38aaa5a68e8c21a6b17dc8b579";
    //     bytes
    //         memory expected_Q1_y = hex"02e98f2ccf5802b05ffaac7c20018bc0c0b2fd580216c4aa2275d2909dc0c92d0d0bdc979226adeb57a29933536b6bb4";

    //     assertEq(result[0], expected_Q0_x);
    //     assertEq(result[1], expected_Q0_y);
    //     assertEq(result[2], expected_Q1_x);
    //     assertEq(result[3], expected_Q1_y);
    // }

    // function test_hash_to_curve_g1_msg_a512() public view {
    //     bytes[4] memory result = hasher.hash_to_curve_g1(
    //         "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    //     );
    //     bytes
    //         memory expected_Q0_x = hex"0cf97e6dbd0947857f3e578231d07b309c622ade08f2c08b32ff372bd90db19467b2563cc997d4407968d4ac80e154f8";
    //     bytes
    //         memory expected_Q0_y = hex"127f0cddf2613058101a5701f4cb9d0861fd6c2a1b8e0afe194fccf586a3201a53874a2761a9ab6d7220c68661a35ab3";
    //     bytes
    //         memory expected_Q1_x = hex"092f1acfa62b05f95884c6791fba989bbe58044ee6355d100973bf9553ade52b47929264e6ae770fb264582d8dce512a";
    //     bytes
    //         memory expected_Q1_y = hex"028e6d0169a72cfedb737be45db6c401d3adfb12c58c619c82b93a5dfcccef12290de530b0480575ddc8397cda0bbebf";

    //     assertEq(result[0], expected_Q0_x);
    //     assertEq(result[1], expected_Q0_y);
    //     assertEq(result[2], expected_Q1_x);
    //     assertEq(result[3], expected_Q1_y);
    // }

    // function test_hash_to_curve_g2_empty_msg() public view {
    //     bytes[8] memory result = hasher.hash_to_curve_g2("");
    //     bytes
    //         memory expected_Q0_x = hex"019ad3fc9c72425a998d7ab1ea0e646a1f6093444fc6965f1cad5a3195a7b1e099c050d57f45e3fa191cc6d75ed7458c";
    //     bytes
    //         memory expected_Q0_x_I = hex"171c88b0b0efb5eb2b88913a9e74fe111a4f68867b59db252ce5868af4d1254bfab77ebde5d61cd1a86fb2fe4a5a1c1d";
    //     bytes
    //         memory expected_Q0_y = hex"0ba10604e62bdd9eeeb4156652066167b72c8d743b050fb4c1016c31b505129374f76e03fa127d6a156213576910fef3";
    //     bytes
    //         memory expected_Q0_y_I = hex"0eb22c7a543d3d376e9716a49b72e79a89c9bfe9feee8533ed931cbb5373dde1fbcd7411d8052e02693654f71e15410a";
    //     bytes
    //         memory expected_Q1_x = hex"113d2b9cd4bd98aee53470b27abc658d91b47a78a51584f3d4b950677cfb8a3e99c24222c406128c91296ef6b45608be";
    //     bytes
    //         memory expected_Q1_x_I = hex"13855912321c5cb793e9d1e88f6f8d342d49c0b0dbac613ee9e17e3c0b3c97dfbb5a49cc3fb45102fdbaf65e0efe2632";
    //     bytes
    //         memory expected_Q1_y = hex"0fd3def0b7574a1d801be44fde617162aa2e89da47f464317d9bb5abc3a7071763ce74180883ad7ad9a723a9afafcdca";
    //     bytes
    //         memory expected_Q1_y_I = hex"056f617902b3c0d0f78a9a8cbda43a26b65f602f8786540b9469b060db7b38417915b413ca65f875c130bebfaa59790c";

    //     assertEq(result[0], expected_Q0_x);
    //     assertEq(result[1], expected_Q0_x_I);
    //     assertEq(result[2], expected_Q0_y);
    //     assertEq(result[3], expected_Q0_y_I);
    //     assertEq(result[4], expected_Q1_x);
    //     assertEq(result[5], expected_Q1_x_I);
    //     assertEq(result[6], expected_Q1_y);
    //     assertEq(result[7], expected_Q1_y_I);
    // }
}
