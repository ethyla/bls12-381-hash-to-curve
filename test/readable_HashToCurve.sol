// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {readable_Hash_to_curve} from "../src/readable_HashToCurve.sol";

contract readable_Hash_to_curveTest is Test {
    readable_Hash_to_curve public hasher;
    bytes DST = "QUUX-V01-CS02-with-expander";

    function setUp() public {
        hasher = new readable_Hash_to_curve();
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

    function test_hash_to_field_empty_msg() public view {
        bytes
            memory custom_dst = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
        bytes[][] memory result = hasher.hash_to_field_fp2("", 2, custom_dst);
        bytes
            memory expected00 = hex"03dbc2cce174e91ba93cbb08f26b917f98194a2ea08d1cce75b2b9cc9f21689d80bd79b594a613d0a68eb807dfdc1cf8";
        bytes
            memory expected01 = hex"05a2acec64114845711a54199ea339abd125ba38253b70a92c876df10598bd1986b739cad67961eb94f7076511b3b39a";
        bytes
            memory expected10 = hex"02f99798e8a5acdeed60d7e18e9120521ba1f47ec090984662846bc825de191b5b7641148c0dbc237726a334473eee94";
        bytes
            memory expected11 = hex"145a81e418d4010cc027a68f14391b30074e89e60ee7a22f87217b2f6eb0c4b94c9115b436e6fa4607e95a98de30a435";

        assertEq(result[0][0], expected00);
        assertEq(result[0][1], expected01);
        assertEq(result[1][0], expected10);
        assertEq(result[1][1], expected11);
    }

    function test_hash_to_field_msg_abc() public view {
        bytes
            memory custom_dst = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
        bytes[][] memory result = hasher.hash_to_field_fp2(
            "abc",
            2,
            custom_dst
        );

        bytes
            memory expected00 = hex"15f7c0aa8f6b296ab5ff9c2c7581ade64f4ee6f1bf18f55179ff44a2cf355fa53dd2a2158c5ecb17d7c52f63e7195771";
        bytes
            memory expected01 = hex"01c8067bf4c0ba709aa8b9abc3d1cef589a4758e09ef53732d670fd8739a7274e111ba2fcaa71b3d33df2a3a0c8529dd";
        bytes
            memory expected10 = hex"187111d5e088b6b9acfdfad078c4dacf72dcd17ca17c82be35e79f8c372a693f60a033b461d81b025864a0ad051a06e4";
        bytes
            memory expected11 = hex"08b852331c96ed983e497ebc6dee9b75e373d923b729194af8e72a051ea586f3538a6ebb1e80881a082fa2b24df9f566";

        assertEq(result[0][0], expected00);
        assertEq(result[0][1], expected01);
        assertEq(result[1][0], expected10);
        assertEq(result[1][1], expected11);
    }

    function test_hash_to_field_msg_abcdef0123456789() public view {
        bytes
            memory custom_dst = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
        bytes[][] memory result = hasher.hash_to_field_fp2(
            "abcdef0123456789",
            2,
            custom_dst
        );

        bytes
            memory expected00 = hex"0313d9325081b415bfd4e5364efaef392ecf69b087496973b229303e1816d2080971470f7da112c4eb43053130b785e1";
        bytes
            memory expected01 = hex"062f84cb21ed89406890c051a0e8b9cf6c575cf6e8e18ecf63ba86826b0ae02548d83b483b79e48512b82a6c0686df8f";
        bytes
            memory expected10 = hex"1739123845406baa7be5c5dc74492051b6d42504de008c635f3535bb831d478a341420e67dcc7b46b2e8cba5379cca97";
        bytes
            memory expected11 = hex"01897665d9cb5db16a27657760bbea7951f67ad68f8d55f7113f24ba6ddd82caef240a9bfa627972279974894701d975";

        assertEq(result[0][0], expected00);
        assertEq(result[0][1], expected01);
        assertEq(result[1][0], expected10);
        assertEq(result[1][1], expected11);
    }

    function test_hash_to_field_msg_q128() public view {
        bytes
            memory custom_dst = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
        bytes[][] memory result = hasher.hash_to_field_fp2(
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            2,
            custom_dst
        );

        bytes
            memory expected00 = hex"025820cefc7d06fd38de7d8e370e0da8a52498be9b53cba9927b2ef5c6de1e12e12f188bbc7bc923864883c57e49e253";
        bytes
            memory expected01 = hex"034147b77ce337a52e5948f66db0bab47a8d038e712123bb381899b6ab5ad20f02805601e6104c29df18c254b8618c7b";
        bytes
            memory expected10 = hex"0930315cae1f9a6017c3f0c8f2314baa130e1cf13f6532bff0a8a1790cd70af918088c3db94bda214e896e1543629795";
        bytes
            memory expected11 = hex"10c4df2cacf67ea3cb3108b00d4cbd0b3968031ebc8eac4b1ebcefe84d6b715fde66bef0219951ece29d1facc8a520ef";

        assertEq(result[0][0], expected00);
        assertEq(result[0][1], expected01);
        assertEq(result[1][0], expected10);
        assertEq(result[1][1], expected11);
    }

    function test_hash_to_field_msg_a512() public view {
        bytes
            memory custom_dst = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
        bytes[][] memory result = hasher.hash_to_field_fp2(
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            2,
            custom_dst
        );

        bytes
            memory expected00 = hex"190b513da3e66fc9a3587b78c76d1d132b1152174d0b83e3c1114066392579a45824c5fa17649ab89299ddd4bda54935";
        bytes
            memory expected01 = hex"12ab625b0fe0ebd1367fe9fac57bb1168891846039b4216b9d94007b674de2d79126870e88aeef54b2ec717a887dcf39";
        bytes
            memory expected10 = hex"0e6a42010cf435fb5bacc156a585e1ea3294cc81d0ceb81924d95040298380b164f702275892cedd81b62de3aba3f6b5";
        bytes
            memory expected11 = hex"117d9a0defc57a33ed208428cb84e54c85a6840e7648480ae428838989d25d97a0af8e3255be62b25c2a85630d2dddd8";

        assertEq(result[0][0], expected00);
        assertEq(result[0][1], expected01);
        assertEq(result[1][0], expected10);
        assertEq(result[1][1], expected11);
    }

    function test_hash_to_field_g1_empty_msg() public view {
        bytes
            memory custom_dst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
        bytes[] memory result = hasher.hash_to_field_fp("", 2, custom_dst);
        bytes
            memory expected0 = hex"0ba14bd907ad64a016293ee7c2d276b8eae71f25a4b941eece7b0d89f17f75cb3ae5438a614fb61d6835ad59f29c564f";
        bytes
            memory expected1 = hex"019b9bd7979f12657976de2884c7cce192b82c177c80e0ec604436a7f538d231552f0d96d9f7babe5fa3b19b3ff25ac9";

        assertEq(result[0], expected0);
        assertEq(result[1], expected1);
    }

    function test_hash_to_field_g1_msg_abc() public view {
        bytes
            memory custom_dst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
        bytes[] memory result = hasher.hash_to_field_fp("abc", 2, custom_dst);
        bytes
            memory expected0 = hex"0d921c33f2bad966478a03ca35d05719bdf92d347557ea166e5bba579eea9b83e9afa5c088573c2281410369fbd32951";
        bytes
            memory expected1 = hex"003574a00b109ada2f26a37a91f9d1e740dffd8d69ec0c35e1e9f4652c7dba61123e9dd2e76c655d956e2b3462611139";

        assertEq(result[0], expected0);
        assertEq(result[1], expected1);
    }

    function test_hash_to_field_g1_msg_abcdef0123456789() public view {
        bytes
            memory custom_dst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
        bytes[] memory result = hasher.hash_to_field_fp(
            "abcdef0123456789",
            2,
            custom_dst
        );
        bytes
            memory expected0 = hex"062d1865eb80ebfa73dcfc45db1ad4266b9f3a93219976a3790ab8d52d3e5f1e62f3b01795e36834b17b70e7b76246d4";
        bytes
            memory expected1 = hex"0cdc3e2f271f29c4ff75020857ce6c5d36008c9b48385ea2f2bf6f96f428a3deb798aa033cd482d1cdc8b30178b08e3a";

        assertEq(result[0], expected0);
        assertEq(result[1], expected1);
    }

    function test_hash_to_field_g1_msg_q128() public view {
        bytes
            memory custom_dst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
        bytes[] memory result = hasher.hash_to_field_fp(
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            2,
            custom_dst
        );
        bytes
            memory expected0 = hex"010476f6a060453c0b1ad0b628f3e57c23039ee16eea5e71bb87c3b5419b1255dc0e5883322e563b84a29543823c0e86";
        bytes
            memory expected1 = hex"0b1a912064fb0554b180e07af7e787f1f883a0470759c03c1b6509eb8ce980d1670305ae7b928226bb58fdc0a419f46e";

        assertEq(result[0], expected0);
        assertEq(result[1], expected1);
    }

    function test_hash_to_field_g1_msg_a512() public view {
        bytes
            memory custom_dst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
        bytes[] memory result = hasher.hash_to_field_fp(
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            2,
            custom_dst
        );
        bytes
            memory expected0 = hex"0a8ffa7447f6be1c5a2ea4b959c9454b431e29ccc0802bc052413a9c5b4f9aac67a93431bd480d15be1e057c8a08e8c6";
        bytes
            memory expected1 = hex"05d487032f602c90fa7625dbafe0f4a49ef4a6b0b33d7bb349ff4cf5410d297fd6241876e3e77b651cfc8191e40a68b7";

        assertEq(result[0], expected0);
        assertEq(result[1], expected1);
    }
}
