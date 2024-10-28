// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use futures::future::join_all;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use regex::Regex;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use sui_swarm_config::genesis_config::{AccountConfig, DEFAULT_GAS_AMOUNT};
use sui_types::base_types::ObjectID;
use surf_strategy::SurfStrategy;
use test_cluster::{TestCluster, TestClusterBuilder};
use tokio::sync::watch;
use tracing::info;

use crate::surfer_state::SurfStatistics;
use crate::surfer_task::SurferTask;

pub mod surf_strategy;
mod surfer_state;
mod surfer_task;

const VALIDATOR_COUNT: usize = 7;

const ACCOUNT_NUM: usize = 20;
const GAS_OBJECT_COUNT: usize = 3;

pub async fn run(
    run_duration: Duration,
    epoch_duration: Duration,
    packages: Vec<PackageSpec>,
    entry_function_exclude_regex: Option<Regex>,
) -> SurfStatistics {
    let cluster = TestClusterBuilder::new()
        .with_num_validators(VALIDATOR_COUNT)
        .with_epoch_duration_ms(epoch_duration.as_millis() as u64)
        .with_accounts(vec![
            AccountConfig {
                address: None,
                gas_amounts: vec![DEFAULT_GAS_AMOUNT; GAS_OBJECT_COUNT],
            };
            ACCOUNT_NUM
        ])
        .build()
        .await;
    info!(
        "Started cluster with {} validators and epoch duration of {:?}ms",
        VALIDATOR_COUNT,
        epoch_duration.as_millis()
    );
    run_with_test_cluster(
        run_duration,
        packages,
        entry_function_exclude_regex,
        cluster.into(),
        0,
    )
    .await
}

pub async fn run_with_test_cluster(
    run_duration: Duration,
    packages: Vec<PackageSpec>,
    entry_function_exclude_regex: Option<Regex>,
    cluster: Arc<TestCluster>,
    // Skips the first N accounts, for use in case this is running concurrently with other
    // processes that also need gas.
    skip_accounts: usize,
) -> SurfStatistics {
    run_with_test_cluster_and_strategy(
        SurfStrategy::default(),
        run_duration,
        packages,
        entry_function_exclude_regex,
        cluster,
        skip_accounts,
    )
    .await
}

pub enum PackageSpec {
    Path(PathBuf), // must be published
    Id(ObjectID),  // already published, just needs to be crawled.
}

impl From<PathBuf> for PackageSpec {
    fn from(path: PathBuf) -> Self {
        PackageSpec::Path(path)
    }
}

impl From<ObjectID> for PackageSpec {
    fn from(id: ObjectID) -> Self {
        PackageSpec::Id(id)
    }
}

pub async fn run_with_test_cluster_and_strategy(
    surf_strategy: SurfStrategy,
    run_duration: Duration,
    package_paths: Vec<PackageSpec>,
    entry_function_exclude_regex: Option<Regex>,
    cluster: Arc<TestCluster>,
    // Skips the first N accounts, for use in case this is running concurrently with other
    // processes that also need gas.
    skip_accounts: usize,
) -> SurfStatistics {
    let seed = rand::thread_rng().gen::<u64>();
    info!("Initial Seed: {:?}", seed);
    let mut rng = StdRng::seed_from_u64(seed);
    let (exit_sender, exit_rcv) = watch::channel(());

    let mut tasks = SurferTask::create_surfer_tasks(
        cluster.clone(),
        rng.gen::<u64>(),
        exit_rcv,
        skip_accounts,
        surf_strategy,
        entry_function_exclude_regex,
    )
    .await;
    info!("Created {} surfer tasks", tasks.len());

    for pkg in &package_paths {
        match pkg {
            PackageSpec::Path(path) => {
                tasks
                    .choose_mut(&mut rng)
                    .unwrap()
                    .state
                    .publish_package(path)
                    .await;
            }
            PackageSpec::Id(id) => {
                tasks
                    .choose_mut(&mut rng)
                    .unwrap()
                    .state
                    .add_package(*id)
                    .await;
            }
        }
    }

    let mut handles = vec![];
    for task in tasks {
        handles.push(tokio::task::spawn(task.surf()));
    }
    tokio::time::sleep(run_duration).await;
    exit_sender.send(()).unwrap();
    let all_stats: Result<Vec<_>, _> = join_all(handles).await.into_iter().collect();
    SurfStatistics::aggregate(all_stats.unwrap())

    // TODO: Right now it will panic here complaining about dropping a tokio runtime
    // inside of another tokio runtime. Reason unclear.
}
