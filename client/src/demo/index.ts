import { getDefaultRestProvider, RestProvider, types, Wallet as SyncWallet } from 'zksync';
import { ethers, utils, Wallet as EthWallet } from 'ethers';
import { EthClient } from './l1client';
import { L2Client } from './l2client';
import { blob } from 'stream/consumers';
import { sleep } from 'zksync/build/utils';
const addresses = require('../constant/addresses.json');
let ethClient: EthClient;
let l2Client: L2Client;
let alice: EthWallet;
let bob: EthWallet;
let aliceAddress: string;
let bobAddress: string;
let l2Alice: SyncWallet;
let l2Bob: SyncWallet;

let restProvider: RestProvider;
let lastTxHash: string;
let lastTxReceipt: types.TransactionReceipt;
const ethToken: string = 'ETH';
const erc20Tokens: string[] = ['DAI', 'wBTC'];
const batchSize: number = 10;
let depositAmount: ethers.BigNumber;
let web3Provider: ethers.providers.BaseProvider;

let tokenAddress: string;
let erc20Contract: ethers.Contract;
const zksyncProxyAddress = '0x1000000000000000000000000000000000000000';
let zksyncProxyContract: ethers.Contract;
const nftFactoryAddress = '0x2000000000000000000000000000000000000000';
let nftFactoryContract: ethers.Contract;
const network = 'localhost';
const TIMEOUT_MS = 10000;
async function init() {
    restProvider = await getDefaultRestProvider('localhost');
    ethClient = await EthClient.init(network);
    l2Client = await L2Client.init(network, ethClient.getEthWallet());
}
export async function logL1Balances() {
    //Layer 1 balances
    let aliceBalances = [],
        bobBalances = [];
    let ethBalance = await ethClient.getBalance(alice);
    aliceBalances.push(`${ethToken}:` + utils.formatEther(ethBalance));
    ethBalance = await ethClient.getBalance(bob);
    bobBalances.push(`${ethToken}:` + utils.formatEther(ethBalance));
    for (const token of erc20Tokens) {
        let tokenBalance = await ethClient.getERC20Balance(aliceAddress, token);
        aliceBalances.push(`${token}:` + l2Client.formatBalance(token, tokenBalance));
        tokenBalance = await ethClient.getERC20Balance(bobAddress, token);
        bobBalances.push(`${token}:` + l2Client.formatBalance(token, tokenBalance));
    }
    console.log('L1#Alice balances:', aliceBalances.join(';'));
    console.log('L1#Bob balances:', bobBalances.join(';'));
}
export async function logL2Balances() {
    //Layer 2 balances
    let aliceBalances = [],
        bobBalances = [];
    let ethBalance = await l2Alice.getBalance(ethToken);
    aliceBalances.push(`${ethToken}:` + utils.formatEther(ethBalance));
    ethBalance = await l2Bob.getBalance(ethToken);
    bobBalances.push(`${ethToken}:` + utils.formatEther(ethBalance));
    for (const token of erc20Tokens) {
        let tokenBalance = await l2Alice.getBalance(token);
        aliceBalances.push(`${token}:` + l2Client.formatBalance(token, tokenBalance));
        tokenBalance = await l2Bob.getBalance(token);
        bobBalances.push(`${token}:` + l2Client.formatBalance(token, tokenBalance));
    }
    console.log('L2#Alice balances:', aliceBalances.join(';'));
    console.log('L2#Bob balances:', bobBalances.join(';'));
}
async function initAddresses() {
    //alice = await ethClient.createRandomWallet('1000.0');
    alice = await ethClient.loadWallet(addresses.alice, '2000.0');
    aliceAddress = await alice.getAddress();
    l2Alice = await l2Client.createL2Wallet(alice);
    //const aliceL1Balance = await alice.getBalance();
    //console.log(`L1#Alice address: ${aliceAddress} with balance ${aliceL1Balance}`);

    //bob = await ethClient.createRandomWallet();
    bob = await ethClient.loadWallet(addresses.bob, '1.0');
    bobAddress = await bob.getAddress();
    l2Bob = await l2Client.createL2Wallet(bob);
    //const bobL1Balance = await bob.getBalance();
    //console.log(`L1#Bob address: ${bobAddress} with balance ${bobL1Balance}`);
}
/*
 * Deposit from L1 to L2
 *
 */
async function initETHData() {
    console.log('InitETHData');
    const thousand = l2Client.parseToken(ethToken, '1000');
    await l2Client.depositERC20Token(alice, ethToken, thousand, true);
    await l2Client.changePubKey(l2Alice, ethToken, true);

    await l2Client.transferERC20Token(alice, bob, ethToken, thousand.div(4));
    await l2Client.changePubKey(l2Bob, ethToken, true);
}
async function initERC20Data() {
    console.log('initERC20Data');
    for (const token of erc20Tokens) {
        console.log(`L2#Deposit 1000 ERC20 token ${token} to Alice address ${aliceAddress}`);
        const thousand = l2Client.parseToken(token, '1000');
        await l2Client.depositERC20Token(alice, token, thousand, true);
        console.log(
            `L2#Transfer 250 ERC20 token ${token} from Alice with address ${aliceAddress} to Bob with address ${bobAddress}`
        );
        await l2Client.transferERC20Token(alice, bob, token, thousand.div(4));
    }
}
async function withdrawToEthereum() {
    //await initAddresses();
    const amount = '100';
    const hundred = l2Client.parseToken(ethToken, amount);
    console.log(`L2#Withdraw ${amount} ${ethToken} from Bob address ${bobAddress}`);
    await l2Client.withdrawToEthereum(bob, ethToken, hundred, true);
    //await l2Client.withdrawPendingBalance(bob, ethToken);
    for (const token of erc20Tokens) {
        console.log(`L2#Withdraw ${amount} ERC20 token ${token} from Bob address ${bobAddress}`);
        const hundred = l2Client.parseToken(token, amount);
        await l2Client.withdrawToEthereum(bob, token, hundred, true);
        //await l2Client.withdrawPendingBalance(bob, token);
    }
}
async function fullExit() {
    let balances = await l2Client.fullExit(alice, ethToken);
    await l2Client.withdrawPendingBalance(alice, ethToken);
    console.log(`Alice ${ethToken} balances:`, balances);
    balances = await l2Client.fullExit(bob, ethToken);
    await l2Client.withdrawPendingBalance(bob, ethToken);
    console.log(`Bob ${ethToken} balances:`, balances);

    for (const token of erc20Tokens) {
        let balances = await l2Client.fullExit(alice, token);
        await l2Client.withdrawPendingBalance(alice, token);
        console.log(`Alice ${token} balances:`, balances);

        balances = await l2Client.fullExit(bob, token);
        await l2Client.withdrawPendingBalance(bob, token);
        console.log(`Bob ${token} balances:`, balances);
    }
}
async function sleeping() {
    console.log(`Waiting for ${TIMEOUT_MS} ms`);
    await sleep(TIMEOUT_MS);
}
/*
    const handle = await alice.syncTransfer({
        to: bob.address(),
        token: 'ETH',
        amount: alice.provider.tokenSet.parseToken('ETH', '1')
    });
    lastTxHash = handle.txHash;
    lastTxHash.replace('sync-tx:', '0x');
    lastTxReceipt = await handle.awaitReceipt();
    */
/*
    restProvider = await getDefaultRestProvider('localhost');
    web3Provider = new ethers.providers.JsonRpcProvider('http://localhost:3002');
    depositAmount = tester.syncProvider.tokenSet.parseToken(token, '1000');
    await tester.testDeposit(alice, token, depositAmount, true);
    await tester.testChangePubKey(alice, token, false);

    tokenAddress = alice.provider.tokenSet.resolveTokenAddress(token);
    const erc20InterfacePath = path.join(process.env['ZKSYNC_HOME'] as string, 'etc', 'web3-abi', 'ERC20.json');
    const erc20Interface = new ethers.utils.Interface(require(erc20InterfacePath));
    erc20Contract = new ethers.Contract(tokenAddress, erc20Interface, alice.ethSigner());

    const zksyncProxyInterfacePath = path.join(
        process.env['ZKSYNC_HOME'] as string,
        'etc',
        'web3-abi',
        'ZkSyncProxy.json'
    );
    const zksyncProxyInterface = new ethers.utils.Interface(require(zksyncProxyInterfacePath));
    zksyncProxyContract = new ethers.Contract(zksyncProxyAddress, zksyncProxyInterface, alice.ethSigner());

    const nftFactoryInterfacePath = path.join(
        process.env['ZKSYNC_HOME'] as string,
        'etc',
        'web3-abi',
        'NFTFactory.json'
    );
    const nftFactoryInterface = new ethers.utils.Interface(require(nftFactoryInterfacePath));
    nftFactoryContract = new ethers.Contract(nftFactoryAddress, nftFactoryInterface, alice.ethSigner());
     */
export async function demo() {
    await init();
    console.log('-----Init addresses-----');
    await initAddresses();
    /*
    await logL1Balances();
    await logL2Balances();
    await sleeping();
    console.log('-----Init data-----');
    await initETHData();
    await initERC20Data();
    await sleeping();
    console.log('-----After init data-----');
    await logL1Balances();
    await logL2Balances();
    */
    console.log('-----Withdraw to Ethereum-----');
    await withdrawToEthereum();
    await sleeping();
    console.log('-----After withdrawal-----');
    await logL1Balances();
    await logL2Balances();
    console.log('-----Full exit-----');
    await fullExit();
    await sleeping();
    console.log('-----After withdrawal-----');
    await logL1Balances();
    await logL2Balances();
}
export async function l1Log() {
    await init();
    console.log('-----Init addresses-----');
    await initAddresses();
    await logL1Balances();
}

export async function l2Log() {
    await init();
    console.log('-----Init addresses-----');
    await initAddresses();
    await logL2Balances();
}
