import { RestProvider, Wallet } from 'zksync';
import { BigNumber, ethers } from 'ethers';
import { TokenLike } from 'zksync/build/types';
import { expect } from 'chai';
import * as zksync from 'zksync';
import { randomBytes as _randomBytes } from 'crypto';
import { arrayify } from '@ethersproject/bytes';

type Network = 'localhost' | 'goerli';

export async function createRestSyncProvider(network: Network, transport: 'WS' | 'HTTP') {
    const syncProvider = await zksync.getDefaultRestProvider(network);
    /*
    const syncProvider =
        providerType === 'REST'
            ? await zksync.getDefaultRestProvider(network)
            : await zksync.getDefaultProvider(network, transport);
    */
    if (network == 'localhost' && transport == 'HTTP') {
        syncProvider.pollIntervalMilliSecs = 50;
    }
    return syncProvider;
}

export async function depositToSyncFromEthereum(
    rollupProvider: Wallet,
    wallet: Wallet,
    token: TokenLike,
    amount: BigNumber,
    approve?: boolean
) {
    const depositHandle = await rollupProvider.depositToSyncFromEthereum({
        depositTo: wallet.address(),
        token: token,
        amount,
        approveDepositAmountForERC20: approve
    });

    const receipt = await depositHandle.awaitReceipt();
    return receipt;
}

export async function transferErc20Token(
    rollupProvider: zksync.SyncProvider,
    sender: Wallet,
    receiver: Wallet,
    token: TokenLike,
    amount: BigNumber
) {
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
}

export async function getRollupBalance(wallet: Wallet, token: TokenLike, type: 'committed' | 'verified' = 'committed') {
    return await wallet.getBalance(token, type);
}

export async function getRollupAccountInfo(
    provider: RestProvider,
    addr: string,
    infoType: 'committed' | 'finalized' | 'full'
) {
    if (infoType == 'full') {
        return await provider.accountFullInfo(addr);
    } else {
        return await provider.accountInfo(addr, infoType);
    }
}

export async function getRollupAccountInfos(provider: RestProvider, addr: string) {
    return await Promise.all([
        provider.accountFullInfo(addr),
        provider.accountInfo(addr, 'committed'),
        provider.accountInfo(addr, 'finalized')
    ]);
}

export function randomBytes(length: number): Uint8Array {
    return arrayify(_randomBytes(length));
}
