import { Command } from 'commander';
import * as utils from '../utils';
//import fs from 'fs';
//import {genesis, server} from "./server";
//import os from "os";
export const command = new Command('demo')
    .description('start zksync demo')
    .option('--scenario', 'run demo scenario')
    .action(async (cmd: Command) => {
        await demo();
    });

export async function demo() {
    console.log('Run demo');
    //await utils.spawn('yarn ts-tests api-test');
}

async function createAccounts() {}
