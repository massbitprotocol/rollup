import
{
    ethers, Wallet
} from "ethers";
import {Address, TokenLike} from "zksync/build/types";
import {SyncProvider , RestProvider} from "zksync";
import * as fs from 'fs';
import { createRestSyncProvider } from "./helper";
import { Network } from "./types";

let web3Url = "http://127.0.0.1:8545";
const ERC20ABI = require("../constant/erc20.abi.json");
const ethConfig = require("../constant/eth.json");
//const ethConfig = JSON.parse(fs.readFileSync("../constant/eth.json", { encoding: 'utf-8' }));
export class EthClient {
    //public contract: ethers.Contract;
    public ethProvider: ethers.providers.Provider;
    public ethWallet: ethers.Wallet;
    public runningFee: ethers.BigNumber;
    public contracts: Map<string, ethers.Contract>;
    constructor(
        public network: Network,
        public syncProvider: RestProvider
    ) {
        //this.contract = new ethers.Contract(syncProvider.contractAddress.mainContract, zksyncAbi, ethWallet);
        this.ethProvider = network == 'localhost'
            ? new ethers.providers.JsonRpcProvider(web3Url)
            : ethers.getDefaultProvider(network);
        this.ethWallet = ethers.Wallet.fromMnemonic(
            ethConfig.test_mnemonic as string,
                "m/44'/60'/0'/0/0"
            ).connect(this.ethProvider);
        this.contracts = new Map<string, ethers.Contract>();
        this.runningFee = ethers.BigNumber.from(0);
    }

    // prettier-ignore
    static async init(network: Network) {
        const syncProvider = await createRestSyncProvider(network, "HTTP");
        return new EthClient(network, syncProvider);
    }
    getEthWallet() {
        return this.ethWallet;
    }
    async getBalance(wallet: Wallet) {
        const balance = await wallet.getBalance();
        return balance;
    }
    async getERC20Balance(address: string, token: string) {
        let contract = this.contracts.get(token);
        if (!contract) {
            const tokenAddress = this.syncProvider.tokenSet.resolveTokenAddress(token);
            //const resolvedAddress = await  this.ethProvider.resolveName(tokenAddress);
            //console.log(resolvedAddress, Provider.isProvider(this.ethProvider));
            contract =  new ethers.Contract(tokenAddress, ERC20ABI, this.ethProvider);
            this.contracts.set(token, contract);
        }
        if (contract) {
            return await contract.balanceOf(address);
        }
    }
    async createRandomWallet(amount?: string) {
        const randomWallet = ethers.Wallet.createRandom().connect(this.ethProvider);
        if (amount) {
            const handle = await this.ethWallet.sendTransaction({
                to: randomWallet.address,
                value: ethers.utils.parseEther(amount)
            });
            await handle.wait();
        }
        return randomWallet;
    }
    async loadWallet(addressInfo: any, amount?: string) {
        let wallet;
        if (addressInfo.mnemonic) {
            wallet = ethers.Wallet.fromMnemonic(addressInfo.mnemonic).connect(this.ethProvider);
        } else {
            wallet = ethers.Wallet.createRandom().connect(this.ethProvider);
            console.log(wallet.address, wallet.mnemonic, wallet.privateKey);
            if (amount) {
                const handle = await this.ethWallet.sendTransaction({
                    to: wallet.address,
                    value: ethers.utils.parseEther(amount)
                });
                await handle.wait();
            }
        }
        return wallet;
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