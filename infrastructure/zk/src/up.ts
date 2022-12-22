import { Command } from 'commander';
import * as utils from './utils';

export async function up() {
    await utils.spawn('docker-compose up -d postgres redis geth dev-ticker dev-liquidity-token-watcher');
}

export const command = new Command('up').description('start development containers').action(up);
