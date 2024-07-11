// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import type { BalanceManager, Pool } from '../types/index.js';
import type { DeepBookConfig } from '../utils/config.js';
import { Transaction } from '@mysten/sui/transactions';
import { DEEP_SCALAR, FLOAT_SCALAR } from '../utils/config.js';

export class GovernanceContract {
	#config: DeepBookConfig;

	constructor(config: DeepBookConfig) {
		this.#config = config;
	}

	stake =
		(pool: Pool, balanceManager: BalanceManager, stakeAmount: number, tx: Transaction = new Transaction())=> {
			const tradeProof = this.#config.balanceManager.generateProof(balanceManager, tx);
			const baseCoin = this.#config.getCoin(pool.baseCoin.key);
			const quoteCoin = this.#config.getCoin(pool.quoteCoin.key);

			return tx.moveCall({
				target: `${this.#config.DEEPBOOK_PACKAGE_ID}::pool::stake`,
				arguments: [
					tx.object(pool.address),
					tx.object(balanceManager.address),
					tradeProof,
					tx.pure.u64(stakeAmount * DEEP_SCALAR),
				],
				typeArguments: [baseCoin.type, quoteCoin.type],
			});
		};

	unstake = (pool: Pool, balanceManager: BalanceManager, tx: Transaction = new Transaction()) => {
		const tradeProof = this.#config.balanceManager.generateProof(balanceManager, tx);
		const baseCoin = this.#config.getCoin(pool.baseCoin.key);
		const quoteCoin = this.#config.getCoin(pool.quoteCoin.key);

		tx.moveCall({
			target: `${this.#config.DEEPBOOK_PACKAGE_ID}::pool::unstake`,
			arguments: [tx.object(pool.address), tx.object(balanceManager.address), tradeProof],
			typeArguments: [baseCoin.type, quoteCoin.type],
		});

		return tx;
	};

	submitProposal =
		(
			pool: Pool,
			balanceManager: BalanceManager,
			takerFee: number,
			makerFee: number,
			stakeRequired: number,
			tx: Transaction = new Transaction()
		) => {
			const tradeProof = this.#config.balanceManager.generateProof(balanceManager, tx);
			const baseCoin = this.#config.getCoin(pool.baseCoin.key);
			const quoteCoin = this.#config.getCoin(pool.quoteCoin.key);

			tx.moveCall({
				target: `${this.#config.DEEPBOOK_PACKAGE_ID}::pool::submit_proposal`,
				arguments: [
					tx.object(pool.address),
					tx.object(balanceManager.address),
					tradeProof,
					tx.pure.u64(takerFee * FLOAT_SCALAR),
					tx.pure.u64(makerFee * FLOAT_SCALAR),
					tx.pure.u64(stakeRequired * DEEP_SCALAR),
				],
				typeArguments: [baseCoin.type, quoteCoin.type],
			});

			return tx;
		};

	vote = (pool: Pool, balanceManager: BalanceManager, proposal_id: string, tx: Transaction = new Transaction()) => {
		const tradeProof = this.#config.balanceManager.generateProof(balanceManager, tx);

		tx.moveCall({
			target: `${this.#config.DEEPBOOK_PACKAGE_ID}::pool::vote`,
			arguments: [
				tx.object(pool.address),
				tx.object(balanceManager.address),
				tradeProof,
				tx.pure.id(proposal_id),
			],
		});

		return tx;
	};
}