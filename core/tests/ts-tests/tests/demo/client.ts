import { ethers } from 'ethers';
import { Address, TokenLike } from 'zksync/build/types';
import { SyncProvider } from 'zksync';
import { Provider } from '@ethersproject/abstract-provider';

type Network = 'localhost' | 'goerli';
let web3Url = 'http://127.0.0.1:8545';
const ERC20ABI = require('./erc20.abi.json');

export class EthClient {
    //public contract: ethers.Contract;
    public ethProvider: ethers.providers.Provider;
    public runningFee: ethers.BigNumber;
    public contracts: Map<string, ethers.Contract>;
    constructor(public network: Network, public syncProvider: SyncProvider) {
        //this.contract = new ethers.Contract(syncProvider.contractAddress.mainContract, zksyncAbi, ethWallet);
        this.ethProvider =
            network == 'localhost' ? new ethers.providers.JsonRpcProvider(web3Url) : ethers.getDefaultProvider(network);
        this.contracts = new Map<string, ethers.Contract>();
        this.runningFee = ethers.BigNumber.from(0);
    }

    // prettier-ignore
    static async init(network: Network, synProvider: SyncProvider) {
        return new EthClient(network, synProvider);
    }
    async getL1Balance(address: Address) {
        let balance = await this.ethProvider.getBalance(address);
        return balance;
    }
    async getL1ERC20Balance(address: ethers.Signer, token: string) {
        let contract = this.contracts.get(token);
        if (!contract) {
            const tokenAddress = this.syncProvider.tokenSet.resolveTokenAddress(token);
            console.log(token, tokenAddress);
            //const resolvedAddress = await  this.ethProvider.resolveName(tokenAddress);
            //console.log(resolvedAddress, Provider.isProvider(this.ethProvider));
            contract = new ethers.Contract('0xb59a57032526f14a6d1aa7daaf9116f4a1e65f3b', ERC20ABI, this.ethProvider);
            console.log(`Create contract for token ${token}`);
            this.contracts.set(token, contract);
        }
        if (contract) {
            return await contract.balanceOf(address.toString());
        }
    }
}
/*
//index.js

const Web3 = require("web3");

const provider =
  "<YOUR_QUIKNODE_HTTP_PROVIDER_HERE>"

const Web3Client = new Web3(new Web3.providers.HttpProvider(provider));

// The minimum ABI required to get the ERC20 Token balance
const minABI = [
  // balanceOf
  {
    constant: true,
    inputs: [{ name: "_owner", type: "address" }],
    name: "balanceOf",
    outputs: [{ name: "balance", type: "uint256" }],
    type: "function",
  },
];
const tokenAddress = "0x0d8775f648430679a709e98d2b0cb6250d2887ef";
const walletAddress = "0x1cf56Fd8e1567f8d663e54050d7e44643aF970Ce";

const contract = new Web3Client.eth.Contract(minABI, tokenAddress);

async function getBalance() {
  const result = await contract.methods.balanceOf(walletAddress).call(); // 29803630997051883414242659

  const format = Web3Client.utils.fromWei(result); // 29803630.997051883414242659

  console.log(format);
}

getBalance();
 */
