const { expect } = require("chai");
const hre = require("hardhat");
let dst_g1 = hre.ethers.toUtf8Bytes("BLS12381G1_XMD:SHA-256_SSWU_RO_TESTGEN");
let dst_g2 = hre.ethers.toUtf8Bytes("BLS12381G2_XMD:SHA-256_SSWU_RO_TESTGEN");

describe("Run rfc hash to curve tests G1", function () {
  it("Should return correct value for empty msg", async function () {
    const hasher = await hre.ethers.deployContract("Hash_to_curve");
    await hasher.waitForDeployment();
    let result = await hasher.hash_to_curve_g1(
      hre.ethers.toUtf8Bytes(""),
      dst_g1
    );
    expect(result.x).to.equal(
      "0x000000000000000000000000000000000576730ab036cbac1d95b38dca905586f28d0a59048db4e8778782d89bff856ddef89277ead5a21e2975c4a6e3d8c79e"
    );
    expect(result.y).to.equal(
      "0x000000000000000000000000000000001273e568bebf1864393c517f999b87c1eaa1b8432f95aea8160cd981b5b05d8cd4a7cf00103b6ef87f728e4b547dd7ae"
    );
  });

  it("Should return correct value for msg abc", async function () {
    const hasher = await hre.ethers.deployContract("Hash_to_curve");
    await hasher.waitForDeployment();
    let result = await hasher.hash_to_curve_g1(
      hre.ethers.toUtf8Bytes("abc"),
      dst_g1
    );
    expect(result.x).to.equal(
      "0x00000000000000000000000000000000061daf0cc00d8912dac1d4cf5a7c32fca97f8b3bf3f805121888e5eb89f77f9a9f406569027ac6d0e61b1229f42c43d6"
    );
    expect(result.y).to.equal(
      "0x000000000000000000000000000000000de1601e5ba02cb637c1d35266f5700acee9850796dc88e860d022d7b9e7e3dce5950952e97861e5bb16d215c87f030d"
    );
  });

  it("Should return correct value for msg abcdef0123456789", async function () {
    const hasher = await hre.ethers.deployContract("Hash_to_curve");
    await hasher.waitForDeployment();
    let result = await hasher.hash_to_curve_g1(
      hre.ethers.toUtf8Bytes("abcdef0123456789"),
      dst_g1
    );
    expect(result.x).to.equal(
      "0x000000000000000000000000000000000fb3455436843e76079c7cf3dfef75e5a104dfe257a29a850c145568d500ad31ccfe79be9ae0ea31a722548070cf98cd"
    );
    expect(result.y).to.equal(
      "0x00000000000000000000000000000000177989f7e2c751658df1b26943ee829d3ebcf131d8f805571712f3a7527ee5334ecff8a97fc2a50cea86f5e6212e9a57"
    );
  });

  it("Should return correct value for msg a512 large", async function () {
    const hasher = await hre.ethers.deployContract("Hash_to_curve");
    await hasher.waitForDeployment();
    let result = await hasher.hash_to_curve_g1(
      hre.ethers.toUtf8Bytes(
        "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      ),
      dst_g1
    );
    expect(result.x).to.equal(
      "0x000000000000000000000000000000000514af2137c1ae1d78d5cb97ee606ea142824c199f0f25ac463a0c78200de57640d34686521d3e9cf6b3721834f8a038"
    );
    expect(result.y).to.equal(
      "0x00000000000000000000000000000000047a85d6898416a0899e26219bca7c4f0fa682717199de196b02b95eaf9fb55456ac3b810e78571a1b7f5692b7c58ab6"
    );
  });
});

describe("Run rfc hash to curve tests G2", function () {
  it("Should return correct value for empty msg", async function () {
    const hasher = await hre.ethers.deployContract("Hash_to_curve");
    await hasher.waitForDeployment();
    let result = await hasher.hash_to_curve_g2(
      hre.ethers.toUtf8Bytes(""),
      dst_g2
    );
    expect(result.x).to.equal(
      "0x000000000000000000000000000000000a650bd36ae7455cb3fe5d8bb1310594551456f5c6593aec9ee0c03d2f6cb693bd2c5e99d4e23cbaec767609314f51d3"
    );
    expect(result.x_I).to.equal(
      "0x000000000000000000000000000000000fbdae26f9f9586a46d4b0b70390d09064ef2afe5c99348438a3c7d9756471e015cb534204c1b6824617a85024c772dc"
    );
    expect(result.y).to.equal(
      "0x000000000000000000000000000000000d8d49e7737d8f9fc5cef7c4b8817633103faf2613016cb86a1f3fc29968fe2413e232d9208d2d74a89bf7a48ac36f83"
    );
    expect(result.y_I).to.equal(
      "0x0000000000000000000000000000000002e5cf8f9b7348428cc9e66b9a9b36fe45ba0b0a146290c3a68d92895b1af0e1f2d9f889fb412670ae8478d8abd4c5aa"
    );
  });

  it("Should return correct value for msg abc", async function () {
    const hasher = await hre.ethers.deployContract("Hash_to_curve");
    await hasher.waitForDeployment();
    let result = await hasher.hash_to_curve_g2(
      hre.ethers.toUtf8Bytes("abc"),
      dst_g2
    );
    expect(result.x).to.equal(
      "0x000000000000000000000000000000001953ce6d4267939c7360756d9cca8eb34aac4633ef35369a7dc249445069888e7d1b3f9d2e75fbd468fbcbba7110ea02"
    );
    expect(result.x_I).to.equal(
      "0x0000000000000000000000000000000003578447618463deb106b60e609c6f7cc446dc6035f84a72801ba17c94cd800583b493b948eff0033f09086fdd7f6175"
    );
    expect(result.y).to.equal(
      "0x000000000000000000000000000000000882ab045b8fe4d7d557ebb59a63a35ac9f3d312581b509af0f8eaa2960cbc5e1e36bb969b6e22980b5cbdd0787fcf4e"
    );
    expect(result.y_I).to.equal(
      "0x000000000000000000000000000000000184d26779ae9d4670aca9b267dbd4d3b30443ad05b8546d36a195686e1ccc3a59194aea05ed5bce7c3144a29ec047c4"
    );
  });

  it("Should return correct value for msg abcdef0123456789", async function () {
    const hasher = await hre.ethers.deployContract("Hash_to_curve");
    await hasher.waitForDeployment();
    let result = await hasher.hash_to_curve_g2(
      hre.ethers.toUtf8Bytes("abcdef0123456789"),
      dst_g2
    );
    expect(result.x).to.equal(
      "0x0000000000000000000000000000000017b461fc3b96a30c2408958cbfa5f5927b6063a8ad199d5ebf2d7cdeffa9c20c85487204804fab53f950b2f87db365aa"
    );
    expect(result.x_I).to.equal(
      "0x00000000000000000000000000000000195fad48982e186ce3c5c82133aefc9b26d55979b6f530992a8849d4263ec5d57f7a181553c8799bcc83da44847bdc8d"
    );
    expect(result.y).to.equal(
      "0x00000000000000000000000000000000174a3473a3af2d0302b9065e895ca4adba4ece6ce0b41148ba597001abb152f852dd9a96fb45c9de0a43d944746f833e"
    );
    expect(result.y_I).to.equal(
      "0x00000000000000000000000000000000005cdf3d984e3391e7e969276fb4bc02323c5924a4449af167030d855acc2600cf3d4fab025432c6d868c79571a95bef"
    );
  });

  it("Should return correct value for msg a512 large", async function () {
    const hasher = await hre.ethers.deployContract("Hash_to_curve");
    await hasher.waitForDeployment();
    let result = await hasher.hash_to_curve_g2(
      hre.ethers.toUtf8Bytes(
        "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      ),
      dst_g2
    );
    expect(result.x).to.equal(
      "0x000000000000000000000000000000000a162306f3b0f2bb326f0c4fb0e1fea020019c3af796dcd1d7264f50ddae94cacf3cade74603834d44b9ab3d5d0a6c98"
    );
    expect(result.x_I).to.equal(
      "0x00000000000000000000000000000000123b6bd9feeba26dd4ad00f8bfda2718c9700dc093ea5287d7711844644eb981848316d3f3f57d5d3a652c6cdc816aca"
    );
    expect(result.y).to.equal(
      "0x0000000000000000000000000000000015c1d4f1a685bb63ee67ca1fd96155e3d091e852a684b78d085fd34f6091e5249ddddbdcf2e7ec82ce6c04c63647eeb7"
    );
    expect(result.y_I).to.equal(
      "0x0000000000000000000000000000000005483f3b96d9252dd4fc0868344dfaf3c9d145e3387db23fa8e449304fab6a7b6ec9c15f05c0a1ea66ff0efcc03e001a"
    );
  });
});
