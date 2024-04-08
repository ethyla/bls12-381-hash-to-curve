// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// used to test for the g1 add precompile at the 0a address
contract EIPTester {
    function testBLS12381G1ADD() public view returns (bytes32[4] memory) {
        bytes32[8] memory input;
        input[
            0
        ] = hex"0000000000000000000000000000000012196c5a43d69224d8713389285f26b9";
        input[
            1
        ] = hex"8f86ee910ab3dd668e413738282003cc5b7357af9a7af54bb713d62255e80f56";
        input[
            2
        ] = hex"0000000000000000000000000000000006ba8102bfbeea4416b710c73e8cce30";
        input[
            3
        ] = hex"32c31c6269c44906f8ac4f7874ce99fb17559992486528963884ce429a992fee";
        input[
            4
        ] = hex"000000000000000000000000000000000001101098f5c39893765766af4512a0";
        input[
            5
        ] = hex"c74e1bb89bc7e6fdf14e3e7337d257cc0f94658179d83320b99f31ff94cd2bac";
        input[
            6
        ] = hex"0000000000000000000000000000000003e1a9f9f44ca2cdab4f43a1a3ee3470";
        input[
            7
        ] = hex"fdf90b2fc228eb3b709fcd72f014838ac82a6d797aeefed9a0804b22ed1ce8f7";

        bytes32[4] memory r;
        r[0] = bytes32(hex"00");
        r[1] = bytes32(hex"aaaaaaaa");
        r[2] = bytes32(hex"abcdef");
        r[3] = bytes32(
            hex"0000000000000000000000000000000000000000000000000000000000010099"
        );

        assembly {
            let success := staticcall(
                100000, /// gas should be 600
                0x0a, // address
                input, //input offset
                256, // input size
                r, // output offset
                128 // output size
            )
            switch success
            case 0 {
                invalid()
            } //fail where we haven't enough gas to make the call
        }

        return r;

        // 000000000000000000000000000000001466e1373ae4a7e7ba885c5f0c3ccfa48cdb50661646ac6b779952f466ac9fc92730dcaed9be831cd1f8c4fefffd5209
        // 000000000000000000000000000000000c1fb750d2285d4ca0378e1e8cdbf6044151867c34a711b73ae818aee6dbe9e886f53d7928cc6ed9c851e0422f609b11
    }
}
