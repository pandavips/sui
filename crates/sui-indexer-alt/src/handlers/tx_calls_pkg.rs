// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use anyhow::Result;
use diesel_async::RunQueryDsl;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::transaction::TransactionDataAPI;

use crate::{db, models::transactions::StoredTxCallsPkg, schema::tx_calls_pkg};

use super::Handler;

pub struct TxCallsPkg;

#[async_trait::async_trait]
impl Handler for TxCallsPkg {
    const NAME: &'static str = "tx_calls_pkg";

    const BATCH_SIZE: usize = 100;
    const CHUNK_SIZE: usize = 1000;
    const MAX_PENDING_SIZE: usize = 10000;

    type Value = StoredTxCallsPkg;

    fn process(checkpoint: &Arc<CheckpointData>) -> Result<Vec<Self::Value>> {
        let CheckpointData {
            transactions,
            checkpoint_summary,
            ..
        } = checkpoint.as_ref();

        let mut values = Vec::new();
        let first_tx = checkpoint_summary.network_total_transactions as usize - transactions.len();

        for (i, tx) in transactions.iter().enumerate() {
            let tx_sequence_number = (first_tx + i) as i64;
            let sender = tx.transaction.sender_address().to_vec();

            let move_calls = tx.transaction.data().transaction_data().move_calls();
            values.extend(move_calls.iter().map(|(package, _, _)| StoredTxCallsPkg {
                tx_sequence_number,
                package: package.to_vec(),
                sender: sender.clone(),
            }));
        }

        Ok(values)
    }

    async fn commit(values: &[Self::Value], conn: &mut db::Connection<'_>) -> Result<usize> {
        Ok(diesel::insert_into(tx_calls_pkg::table)
            .values(values)
            .on_conflict_do_nothing()
            .execute(conn)
            .await?)
    }
}
