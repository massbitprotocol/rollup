import {Tester} from "../tester/tester";
import {getDefaultRestProvider, RestProvider, types, Wallet} from "zksync";
import * as ethers from "ethers";
import '../tester/priority-ops';
import '../tester/change-pub-key';
import '../tester/transfer';
import '../tester/withdraw';
import '../tester/forced-exit';
import '../tester/mint-nft';
import { expect } from 'chai';
import path from "path";
import {
    depositToSyncFromEthereum,
    getRollupAccountInfo,
    getRollupAccountInfos,
    getRollupBalance,
    transferErc20Token
} from "./helper";
import {EthClient} from "./client";

describe('Massbit rollup demos', () => {
    let l1Client: EthClient;
    let tester: Tester;
    let alice: Wallet;
    let bob: Wallet;
    let restProvider: RestProvider;
    let lastTxHash: string;
    let lastTxReceipt: types.TransactionReceipt;
    const ethToken: string = 'ETH';
    const batchSize: number = 10;
    let depositAmount: ethers.BigNumber;
    let web3Provider: ethers.ethers.providers.BaseProvider;

    let tokenAddress: string;
    let erc20Contract: ethers.Contract;
    const zksyncProxyAddress = '0x1000000000000000000000000000000000000000';
    let zksyncProxyContract: ethers.Contract;
    const nftFactoryAddress = '0x2000000000000000000000000000000000000000';
    let nftFactoryContract: ethers.Contract;
    before('create client and test wallets', async () => {
        restProvider = await getDefaultRestProvider('localhost');
        tester = await Tester.init('localhost', 'HTTP', 'RPC');
        l1Client = await EthClient.init('localhost', tester.syncProvider);
        alice = await tester.fundedWallet('100.0');
        const aliceL1Balance = await l1Client.getL1Balance(alice.address());
        console.log(`Alice address: ${alice.address()} with L1 balance ${aliceL1Balance}`);

        bob = await tester.emptyWallet();
        const bobL1Balance = await l1Client.getL1Balance(bob.address());
        console.log(`Bob address: ${bob.address()} with L1 balance ${bobL1Balance}`);
        for (const token of ['ETH', 'DAI', 'wBTC']) {
            const thousand = tester.syncProvider.tokenSet.parseToken(token, '1000');
            await tester.testDeposit(alice, token, thousand, true);
            if (token !== 'ETH') {
                let tokenBalance = await l1Client.getL1ERC20Balance(alice.ethSigner(), token);
                console.log(`Alice token ${token} balance: ${tokenBalance}`);
            }
            if (token === 'ETH') await tester.testChangePubKey(alice, token, false);
            await tester.testTransfer(alice, bob, token, thousand.div(4));
        }

        const handle = await alice.syncTransfer({
            to: bob.address(),
            token: 'ETH',
            amount: alice.provider.tokenSet.parseToken('ETH', '1')
        });
        lastTxHash = handle.txHash;
        lastTxHash.replace('sync-tx:', '0x');
        lastTxReceipt = await handle.awaitReceipt();
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
    });
    it("Deposit ERC20 tokens to L2", async () => {
        console.log("Balances of Alice:");
        const rawAmount = 10;
        for (const token of ['ETH', 'DAI', 'wBTC']) {
            const amount = tester.syncProvider.tokenSet.parseToken(token, rawAmount.toString());
            const balanceBefore = await getRollupBalance(alice, token);
            const depositAmount = rawAmount * batchSize;
            for (let i = 0; i < batchSize; i++) {
                await depositToSyncFromEthereum(tester.syncWallet, alice,token, amount, true);
            }
            const balanceAfter = await getRollupBalance(alice, token);
            console.log(`Token: ${token}. Before deposit: ${balanceBefore}, After deposit: ${balanceAfter}; Deposit amount: ${depositAmount}`);
        }
        //Get account scope
        let aliceFullAccountInfo = await getRollupAccountInfo(restProvider, alice.address(), "full");
        let aliceCommitedAccountInfo = await getRollupAccountInfo(restProvider, alice.address(), "committed");
        let aliceFinalizedAccountInfo = await getRollupAccountInfo(restProvider, alice.address(), "finalized");
        console.log("Account infos:", aliceFullAccountInfo, aliceCommitedAccountInfo, aliceFinalizedAccountInfo);
    })
    it('Transfers ERC20 token', async () => {
        const token = "DAI";
        const rawAmount = 2;
        const amount = tester.syncProvider.tokenSet.parseToken(token, rawAmount.toString());
        const aliceBefore = await getRollupBalance(alice, token);
        const bobBefore = await getRollupBalance(bob, token);
        const transferAmount = rawAmount * batchSize;
        for (let i = 0; i < batchSize; i++) {
            await transferErc20Token(tester.syncProvider, alice, bob, token, amount);
        }
        const aliceAfter = await getRollupBalance(alice, token);
        const bobAfter = await getRollupBalance(bob, token);
        let aliceAccountInfos = await getRollupAccountInfos(restProvider, alice.address());
        let bobAccountInfos = await getRollupAccountInfos(restProvider, alice.address());
        console.log("Alice account infos: ", aliceAccountInfos);
        console.log("Bob account infos: ", bobAccountInfos);
        console.log(`Sender token balances ${token}: Before transfer: ${aliceBefore}; After transfer: ${aliceAfter}; Amount: ${transferAmount}`);
        console.log(`Receiver token balances ${token}: Before transfer: ${bobBefore}; After transfer: ${bobAfter}`);
    })

    it('withdrawFromRollupToEthereum', async () => {
        console.log("withdrawFromRollupToEthereum");
        /*
        const type = fastProcessing ? 'FastWithdraw' : 'Withdraw';
        const { totalFee: fee } = await this.syncProvider.getTransactionFee(type, wallet.address(), token);
        const balanceBefore = await wallet.getBalance(token);

        const handle = await wallet.withdrawFromSyncToEthereum({
            ethAddress: wallet.address(),
            token,
            amount,
            fee,
            fastProcessing
        });

        const receipt = await handle.awaitReceipt();
        expect(receipt.success, `Withdraw transaction failed with a reason: ${receipt.failReason}`).to.be.true;

        const balanceAfter = await wallet.getBalance(token);
        expect(balanceBefore.sub(balanceAfter).eq(amount.add(fee)), 'Wrong amount in wallet after withdraw').to.be.true;
        this.runningFee = this.runningFee.add(fee);
        return handle;
         */
    })

    it('withdrawFromEthereum without exit', async () => {
        console.log('withdrawFromEthereum');
    })
})