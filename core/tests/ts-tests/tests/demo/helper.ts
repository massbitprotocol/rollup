import {RestProvider, Wallet} from "zksync";
import {BigNumber} from "ethers";
import {TokenLike} from "zksync/build/types";
import {expect} from "chai";
import * as zksync from "zksync";

export async function depositToSyncFromEthereum(rollupProvider: Wallet, wallet: Wallet, token: TokenLike, amount: BigNumber, approve?: boolean) {
    const depositHandle = await rollupProvider.depositToSyncFromEthereum({
        depositTo: wallet.address(),
        token: token,
        amount,
        approveDepositAmountForERC20: approve
    });

    const receipt = await depositHandle.awaitReceipt();
    return receipt;
}

export async function transferErc20Token(rollupProvider: zksync.SyncProvider, sender: Wallet, receiver: Wallet, token: TokenLike, amount: BigNumber) {
    const fullFee = await rollupProvider.getTransactionFee('Transfer', receiver.address(), token);
    const fee = fullFee.totalFee;
    const handle = await sender.syncTransfer({
        to: receiver.address(),
        token,
        amount,
        fee
    });

    const receipt = await handle.awaitReceipt();
    expect(receipt.success, `Transfer transaction failed with a reason: ${receipt.failReason}`).to.be.true;
    return receipt;
    //this.runningFee = this.runningFee.add(fee);
};

export async function getRollupBalance(wallet: Wallet, token: TokenLike, type: 'committed' | 'verified' = 'committed') {
    return await wallet.getBalance(token, type);
}

export async function getRollupAccountInfo(provider: RestProvider, addr: string, infoType: "committed" | "finalized" | "full") {
    if (infoType == "full") {
        return await provider.accountFullInfo(addr);
    } else {
        return await provider.accountInfo(addr, infoType);
    }
}

export async function getRollupAccountInfos(provider: RestProvider, addr: string) {
    return await Promise.all([provider.accountFullInfo(addr),
        provider.accountInfo(addr, "committed"),
        provider.accountInfo(addr, "finalized")]);
}