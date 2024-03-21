const { expect } = require("chai");
const hre = require("hardhat");

describe("Check if EIP enabled", function () {
  it("Should return a value other than 0", async function () {
    const tester = await hre.ethers.deployContract("EIP_tester");
    await tester.waitForDeployment();

    let result = await tester.test_BLS12_G1ADD();
    console.log(result);
    expect(result[0]).toNot.equal(
      "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
  });
});
