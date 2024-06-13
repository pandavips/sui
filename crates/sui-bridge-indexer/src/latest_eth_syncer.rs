// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The EthSyncer module is responsible for synchronizing Events emitted on Ethereum blockchain from
//! concerned contracts. Each contract is associated with a start block number, and the syncer will
//! only query from that block number onwards. The syncer also keeps track of the last
//! block on Ethereum and will only query for events up to that block number.

use ethers::providers::{Http, Middleware, Provider};
use ethers::types::Address as EthAddress;
use mysten_metrics::spawn_logged_monitored_task;
use std::collections::HashMap;
use std::sync::Arc;
use sui_bridge::error::BridgeResult;
use sui_bridge::eth_client::EthClient;
use sui_bridge::retry_with_max_elapsed_time;
use sui_bridge::types::EthLog;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};
use tracing::error;

const ETH_LOG_QUERY_MAX_BLOCK_RANGE: u64 = 1000;
const ETH_EVENTS_CHANNEL_SIZE: usize = 1000;
const BLOCK_QUERY_INTERVAL: Duration = Duration::from_secs(2);

pub struct LatestEthSyncer<P> {
    eth_client: Arc<EthClient<P>>,
    provider: Arc<Provider<Http>>,
    contract_addresses: EthTargetAddresses,
}

/// Map from contract address to their start block.
pub type EthTargetAddresses = HashMap<EthAddress, u64>;

#[allow(clippy::new_without_default)]
impl<P> LatestEthSyncer<P>
where
    P: ethers::providers::JsonRpcClient + 'static,
{
    pub fn new(
        eth_client: Arc<EthClient<P>>,
        provider: Arc<Provider<Http>>,
        contract_addresses: EthTargetAddresses,
    ) -> Self {
        Self {
            eth_client,
            provider,
            contract_addresses,
        }
    }

    pub async fn run(
        self,
    ) -> BridgeResult<(
        Vec<JoinHandle<()>>,
        mysten_metrics::metered_channel::Receiver<(EthAddress, u64, Vec<EthLog>)>,
        watch::Receiver<u64>,
    )> {
        let (eth_evnets_tx, eth_events_rx) = mysten_metrics::metered_channel::channel(
            ETH_EVENTS_CHANNEL_SIZE,
            &mysten_metrics::get_metrics()
                .unwrap()
                .channel_inflight
                .with_label_values(&["eth_events_queue"]),
        );
        let latest_block = self.provider.get_block_number().await?.as_u64();
        let (latest_block_tx, latest_block_rx) = watch::channel(latest_block);
        let mut task_handles = vec![];
        task_handles.push(spawn_logged_monitored_task!(Self::run_block_refresh_task(
            latest_block_tx,
            self.provider
        )));
        for (contract_address, start_block) in self.contract_addresses {
            let eth_events_tx_clone = eth_evnets_tx.clone();
            let latest_block_rx_clone = latest_block_rx.clone();
            let eth_client_clone = self.eth_client.clone();
            task_handles.push(spawn_logged_monitored_task!(
                Self::run_event_listening_task(
                    contract_address,
                    start_block,
                    latest_block_rx_clone,
                    eth_events_tx_clone,
                    eth_client_clone,
                )
            ));
        }
        Ok((task_handles, eth_events_rx, latest_block_rx))
    }

    async fn run_block_refresh_task(
        latest_block_sender: watch::Sender<u64>,
        provider: Arc<Provider<Http>>,
    ) {
        tracing::info!("Starting block refresh task.");
        let mut latest_block_number = 0;
        let mut interval = time::interval(BLOCK_QUERY_INTERVAL);
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let Ok(Ok(new_value)) = retry_with_max_elapsed_time!(
                provider.get_block_number(),
                time::Duration::from_secs(10)
            ) else {
                error!("Failed to get latest block from eth client after retry");
                continue;
            };
            tracing::debug!("Last block: {}", new_value);

            // TODO add a metrics for the last block

            if new_value.as_u64() > latest_block_number {
                latest_block_sender
                    .send(new_value.as_u64())
                    .expect("last_block channel receiver is closed");
                tracing::info!("Observed new eth block: {}", new_value);
                latest_block_number = new_value.as_u64();
            }
        }
    }

    async fn run_event_listening_task(
        contract_address: EthAddress,
        mut start_block: u64,
        mut latest_block_receiver: watch::Receiver<u64>,
        events_sender: mysten_metrics::metered_channel::Sender<(EthAddress, u64, Vec<EthLog>)>,
        eth_client: Arc<EthClient<P>>,
    ) {
        tracing::info!(contract_address=?contract_address, "Starting eth events listening task from block {start_block}");
        let mut more_blocks = false;
        loop {
            // If no more known blocks, wait for the next block.
            if !more_blocks {
                latest_block_receiver
                    .changed()
                    .await
                    .expect("last_block channel sender is closed");
            }
            let new_block = *latest_block_receiver.borrow();
            if new_block < start_block {
                tracing::info!(
                    contract_address=?contract_address,
                    "New block {} is smaller than start block {}, ignore",
                    new_block,
                    start_block,
                );
                continue;
            }
            // Each query does at most ETH_LOG_QUERY_MAX_BLOCK_RANGE blocks.
            let end_block =
                std::cmp::min(start_block + ETH_LOG_QUERY_MAX_BLOCK_RANGE - 1, new_block);
            more_blocks = end_block < new_block;
            let Ok(Ok(events)) = retry_with_max_elapsed_time!(
                eth_client.get_events_in_range(contract_address, start_block, end_block),
                Duration::from_secs(30)
            ) else {
                error!("Failed to get events from eth client after retry");
                continue;
            };
            let len = events.len();

            // Note 1: we always events to the channel even when it is empty. This is because of
            // how `eth_getLogs` api is designed - we want cursor to move forward continuously.

            // Note 2: it's extremely critical to make sure the Logs we send via this channel
            // are complete per block height. Namely, we should never send a partial list
            // of events for a block. Otherwise, we may end up missing events.
            events_sender
                .send((contract_address, end_block, events))
                .await
                .expect("All Eth event channel receivers are closed");
            if len != 0 {
                tracing::info!(
                    ?contract_address,
                    start_block,
                    end_block,
                    "Observed {len} new Eth events",
                );
            }
            start_block = end_block + 1;
        }
    }
}