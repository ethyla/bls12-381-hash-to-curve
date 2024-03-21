require("@nomicfoundation/hardhat-toolbox");
require("@nomicfoundation/hardhat-foundry");

// /** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  defaultNetwork: "local",
  networks: {
    hardhat: {},
    local: {
      url: "http://127.0.0.1:8545",
      // accounts: [],
    },
  },
  solidity: "0.8.24",
};
