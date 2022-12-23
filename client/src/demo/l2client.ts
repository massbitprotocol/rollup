import { expect } from 'chai';
import { BigNumber, BigNumberish, ethers } from 'ethers';
import { formatUnits } from 'ethers/lib/utils';
import { SyncProvider, Wallet, Signer, RestProvider, types, ETHProxy } from 'zksync';
import { ChangePubkeyTypes } from 'zksync/build/types';
import { createRestSyncProvider, randomBytes } from './helper';
import { Network, TokenLike } from './types';

export class L2Client {
    public runningFee: ethers.BigNumber;
    constructor(public network: Network, public syncProvider: RestProvider, public syncWallet: Wallet) {
        this.runningFee = ethers.BigNumber.from(0);
    }

    // prettier-ignore
    static async init(network: Network, ethWallet: ethers.Wallet) {
      const syncProvider = await createRestSyncProvider(network, "HTTP");
      const syncWallet = await Wallet.fromEthSigner(ethWallet, syncProvider);
      return new L2Client(network, syncProvider, syncWallet);
  }
    async createL2Wallet(ethWallet: ethers.Wallet) {
        const syncWallet = await Wallet.fromEthSigner(ethWallet, this.syncProvider);
        return syncWallet;
    }
    parseToken(token: TokenLike, amount: string) {
        return this.syncProvider.tokenSet.parseToken(token, amount);
    }
    formatBalance(token: TokenLike, balance: BigNumberish) {
        const decimals = this.syncProvider.tokenSet.resolveTokenDecimals(token);
        return formatUnits(balance, decimals);
    }
    resetRunningFee() {
        this.runningFee = ethers.BigNumber.from(0);
    }
    async changePubKey(wallet: Wallet, feeToken: TokenLike, onchain: boolean) {
        if (await wallet.isSigningKeySet()) return;

        const ethAuthType: ChangePubkeyTypes = onchain ? 'Onchain' : 'ECDSA';

        const feeType = { ChangePubKey: ethAuthType };
        let { totalFee: fee } = await this.syncProvider.getTransactionFee(feeType, wallet.address(), feeToken);

        if (onchain) {
            const handle = await wallet.onchainAuthSigningKey();
            await handle.wait();
            expect(await wallet.isOnchainAuthSigningKeySet(), 'ChangePubKey is unset onchain').to.be.true;
        }

        const changePubkeyHandle = await wallet.setSigningKey({
            feeToken,
            fee,
            ethAuthType
        });

        const receipt = await changePubkeyHandle.awaitReceipt();
        expect(receipt.success, `ChangePubKey transaction failed with a reason: ${receipt.failReason}`).to.be.true;
        expect(await wallet.isSigningKeySet(), 'ChangePubKey failed').to.be.true;
        expect(await wallet.isCorrespondingSigningKeySet(), 'ChangePubKey failed').to.be.true;
        const oldSigner = wallet.signer;
        wallet.signer = await Signer.fromSeed(randomBytes(32));
        expect(await wallet.isSigningKeySet(), 'ChangePubKey failed').to.be.true;
        expect(await wallet.isCorrespondingSigningKeySet(), 'Wrong signer for ChangePubKey failed').to.be.false;
        wallet.signer = oldSigner;
        const accountState = await wallet.getAccountState();
        expect(accountState.accountType, 'Incorrect account type').to.be.eql('Owned');

        this.runningFee = this.runningFee.add(fee);
    }
    async depositERC20Token(ethWallet: ethers.Wallet, token: TokenLike, amount: BigNumber, approve?: boolean) {
        const syncWallet = await Wallet.fromEthSigner(ethWallet, this.syncProvider);
        const balanceBefore = this.formatBalance(token, await syncWallet.getBalance(token));
        const depositHandle = await this.syncWallet.depositToSyncFromEthereum({
            depositTo: syncWallet.address(),
            token: token,
            amount,
            approveDepositAmountForERC20: approve
        });

        const receipt = await depositHandle.awaitReceipt();

        const balanceAfter = this.formatBalance(token, await syncWallet.getBalance(token));
        const formatedAmount = this.formatBalance(token, amount);
        console.log(`L2#balances after deposit ${formatedAmount} ${token}: ${balanceBefore} -> ${balanceAfter}`);
        //const currentDate = new Date();
        //console.log('Waiting for verified with ZK Proof at ', currentDate);
        //const receiptAfterVerify = await depositHandle.awaitVerifyReceipt();
        //console.log('Verified with ZK Proof in ', new Date().getTime() - currentDate.getTime(), ' ms');
    }
    async transferERC20Token(sender: ethers.Wallet, receipent: ethers.Wallet, token: TokenLike, amount: BigNumber) {
        const l2SenderWallet = await Wallet.fromEthSigner(sender, this.syncProvider);
        const l2ReceipentWallet = await Wallet.fromEthSigner(receipent, this.syncProvider);
        const fullFee = await this.syncProvider.getTransactionFee('Transfer', l2ReceipentWallet.address(), token);
        const fee = fullFee.totalFee;
        const senderBefore = await l2SenderWallet.getBalance(token);
        const receiverBefore = await l2ReceipentWallet.getBalance(token);

        const handle = await l2SenderWallet.syncTransfer({
            to: l2ReceipentWallet.address(),
            token,
            amount,
            fee
        });

        // this function will return when deposit is committed to the zkSync chain
        const receipt = await handle.awaitReceipt();
        expect(receipt.success, `Transfer transaction failed with a reason: ${receipt.failReason}`).to.be.true;
        const senderAfter = await l2SenderWallet.getBalance(token);
        const receiverAfter = await l2ReceipentWallet.getBalance(token);

        if (l2SenderWallet.address() === l2ReceipentWallet.address()) {
            expect(senderBefore.sub(fee).eq(senderAfter), 'Transfer to self failed').to.be.true;
        } else {
            expect(senderBefore.sub(senderAfter).eq(amount.add(fee)), 'Transfer failed (incorrect sender balance)').to
                .be.true;
            expect(receiverAfter.sub(receiverBefore).eq(amount), 'Transfer failed (incorrect receiver balance)').to.be
                .true;
        }

        this.runningFee = this.runningFee.add(fee);
        // this function will return when deposit is verified with ZK proof.
        //const currentDate = new Date();
        //console.log('Waiting for verified with ZK Proof at ', currentDate);
        //const receiptAfterVerify = await handle.awaitVerifyReceipt();
        //console.log('Verified with ZK Proof in ', new Date().getTime() - currentDate.getTime(), 'ms');
    }

    async getAccountInfo(idOrAddress: string | number, infoType: 'committed' | 'finalized') {
        return this.syncProvider.accountInfo(idOrAddress, infoType);
    }

    async getAccountFullInfo(idOrAddress: string | number) {
        return this.syncProvider.accountFullInfo(idOrAddress);
    }

    async withdrawToEthereum(
        etherWallet: ethers.Wallet,
        token: TokenLike,
        amount: BigNumber,
        fastProcessing?: boolean
    ) {
        const type = fastProcessing ? 'FastWithdraw' : 'Withdraw';
        const wallet = await Wallet.fromEthSigner(etherWallet, this.syncProvider);
        const address = wallet.address();
        const { totalFee: fee } = await this.syncProvider.getTransactionFee(type, address, token);
        const balanceBefore = await wallet.getBalance(token);

        const handle = await wallet.withdrawFromSyncToEthereum({
            ethAddress: address,
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
        // this function will return when deposit is verified with ZK proof.
        //const receiptAfterVerify = await handle.awaitVerifyReceipt();
        return handle;
    }

    async withdrawNFT(etherWallet: ethers.Wallet, withdrawer: Signer, feeToken: TokenLike, fastProcessing?: boolean) {
        const type = fastProcessing ? 'FastWithdrawNFT' : 'WithdrawNFT';
        const wallet = await Wallet.fromEthSigner(etherWallet, this.syncProvider);
        const { totalFee: fee } = await this.syncProvider.getTransactionFee(type, wallet.address(), feeToken);

        const state = await wallet.getAccountState();
        let nft: types.NFT = Object.values(state.committed.nfts)[0];
        expect(nft !== undefined);

        const balanceBefore = await wallet.getNFT(nft.id);
        expect(balanceBefore.id == nft.id, 'Account does not have an NFT initially').to.be.true;

        const handle = await wallet.withdrawNFT({
            to: wallet.address(),
            token: nft.id,
            feeToken,
            fee,
            fastProcessing
        });

        const receipt = await handle.awaitReceipt();
        expect(receipt.success, `Withdraw transaction failed with a reason: ${receipt.failReason}`).to.be.true;

        const balanceAfter = await wallet.getNFT(nft.id);
        expect(balanceAfter === undefined, 'Account has an NFT after withdrawing').to.be.true;

        // Checking that the metadata was saved correctly
        await handle.awaitVerifyReceipt();
        /*
    const ethProxy = new ETHProxy(this.ethProvider, await this.syncProvider.getContractAddress());
    await ethProxy.getZkSyncContract().connect(withdrawer).withdrawPendingNFTBalance(nft.id);
    const defaultFactory = await ethProxy.getDefaultNFTFactory();
  
    const creatorId = await defaultFactory.getCreatorAccountId(nft.id);
    const contentHash = await defaultFactory.getContentHash(nft.id);
  
    expect(creatorId).to.eq(nft.creatorId, 'The creator id was not saved correctly');
    expect(contentHash).to.eq(nft.contentHash, 'The content hash was not saved correctly');
    */
        this.runningFee = this.runningFee.add(fee);
    }

    async fullExit(etherWallet: ethers.Wallet, token: TokenLike, accountId?: number) {
        const wallet = await Wallet.fromEthSigner(etherWallet, this.syncProvider);
        const balanceBefore = await wallet.getBalance(token);
        const handle = await wallet.emergencyWithdraw({ token, accountId });
        let receipt = await handle.awaitReceipt();
        expect(receipt.executed, 'Full Exit was not executed').to.be.true;
        const balanceAfter = await wallet.getBalance(token);
        return [balanceBefore, balanceAfter];
    }

    async fullExitNFT(etherWallet: ethers.Wallet, accountId?: number) {
        const wallet = await Wallet.fromEthSigner(etherWallet, this.syncProvider);
        const state = await wallet.getAccountState();
        let nft: any = Object.values(state.verified.nfts)[0];
        expect(nft !== undefined);
        const balanceBefore = await wallet.getNFT(nft.id);
        expect(balanceBefore.id == nft.id, 'Account does not have an NFT initially').to.be.true;

        const handle = await wallet.emergencyWithdrawNFT({ tokenId: nft.id, accountId });
        let receipt = await handle.awaitReceipt();
        expect(receipt.executed, 'NFT Full Exit was not executed').to.be.true;

        const balanceAfter = await wallet.getNFT(nft.id);
        expect(balanceAfter === undefined, 'Account has an NFT after Full Exit').to.be.true;
    }

    async withdrawPendingBalance(etherWallet: ethers.Wallet, token: TokenLike, amount?: BigNumberish) {
        const wallet = await Wallet.fromEthSigner(etherWallet, this.syncProvider);
        const address = wallet.address();
        const withdrawPendingTx = await wallet.withdrawPendingBalance(address, token, amount);
        const txReceipt = await withdrawPendingTx.wait();
        console.log(`WithdrawPendingBalance token ${token} from address ${address} with tran:`, txReceipt);
        return txReceipt;
    }
}
