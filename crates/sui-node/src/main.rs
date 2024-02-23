// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::{ArgGroup, Parser};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Notify};
use tokio::time::sleep;
use tracing::{error, info};

use mysten_common::sync::async_once_cell::AsyncOnceCell;
use mysten_metrics::RegistryService;
use sui_config::node::RunWithRange;
use sui_config::{Config, NodeConfig};
use sui_core::runtime::SuiRuntimes;
use sui_node::health_check;
use sui_node::metrics;
use sui_protocol_config::SupportedProtocolVersions;
use sui_telemetry::send_telemetry_event;
use sui_types::committee::EpochId;
use sui_types::messages_checkpoint::CheckpointSequenceNumber;
use sui_types::multiaddr::Multiaddr;

const GIT_REVISION: &str = {
    if let Some(revision) = option_env!("GIT_REVISION") {
        revision
    } else {
        let version = git_version::git_version!(
            args = ["--always", "--abbrev=12", "--dirty", "--exclude", "*"],
            fallback = ""
        );

        if version.is_empty() {
            panic!("unable to query git revision");
        }
        version
    }
};
const VERSION: &str = const_str::concat!(env!("CARGO_PKG_VERSION"), "-", GIT_REVISION);

#[derive(Parser)]
#[clap(rename_all = "kebab-case")]
#[clap(name = env!("CARGO_BIN_NAME"))]
#[clap(version = VERSION)]
#[clap(group(ArgGroup::new("exclusive").required(false)))]
struct Args {
    #[clap(long)]
    pub config_path: PathBuf,

    #[clap(long, help = "Specify address to listen on")]
    listen_address: Option<Multiaddr>,

    #[clap(long, group = "exclusive")]
    run_with_range_epoch: Option<EpochId>,

    #[clap(long, group = "exclusive")]
    run_with_range_checkpoint: Option<CheckpointSequenceNumber>,
}

fn main() {
    // Ensure that a validator never calls get_for_min_version/get_for_max_version_UNSAFE.
    // TODO: re-enable after we figure out how to eliminate crashes in prod because of this.
    // ProtocolConfig::poison_get_for_min_version();

    move_vm_profiler::gas_profiler_feature_enabled! {
        panic!("Cannot run the sui-node binary with gas-profiler feature enabled");
    }

    let args = Args::parse();
    let mut config = NodeConfig::load(&args.config_path).unwrap();
    assert!(
        config.supported_protocol_versions.is_none(),
        "supported_protocol_versions cannot be read from the config file"
    );
    config.supported_protocol_versions = Some(SupportedProtocolVersions::SYSTEM_DEFAULT);

    // match run_with_range args
    // this means that we always modify the config used to start the node
    // for run_with_range. i.e if this is set in the config, it is ignored. only the cli args
    // enable/disable run_with_range
    match (args.run_with_range_epoch, args.run_with_range_checkpoint) {
        (None, Some(checkpoint)) => {
            config.run_with_range = Some(RunWithRange::Checkpoint(checkpoint))
        }
        (Some(epoch), None) => config.run_with_range = Some(RunWithRange::Epoch(epoch)),
        _ => config.run_with_range = None,
    };

    let runtimes = SuiRuntimes::new(&config);
    let metrics_rt = runtimes.metrics.enter();
    let registry_service = mysten_metrics::start_prometheus_server(config.metrics_address);
    let prometheus_registry = registry_service.default_registry();

    // Initialize logging
    let (_guard, filter_handle) = telemetry_subscribers::TelemetryConfig::new()
        .with_env()
        .with_prom_registry(&prometheus_registry)
        .init();

    drop(metrics_rt);

    info!("Sui Node version: {VERSION}");
    info!(
        "Supported protocol versions: {:?}",
        config.supported_protocol_versions
    );

    info!(
        "Started Prometheus HTTP endpoint at {}",
        config.metrics_address
    );

    let notify = Arc::new(Notify::new());
    {
        let _enter = runtimes.metrics.enter();
        metrics::start_metrics_push_task(&config, registry_service.clone(), notify.clone());
    }

    if let Some(listen_address) = args.listen_address {
        config.network_address = listen_address;
    }

    let is_validator = config.consensus_config().is_some();

    let admin_interface_port = config.admin_interface_port;

    // Run node in a separate runtime so that admin/monitoring functions continue to work
    // if it deadlocks.
    let node_once_cell = Arc::new(AsyncOnceCell::<Arc<sui_node::SuiNode>>::new());
    let node_once_cell_clone = node_once_cell.clone();
    let rpc_runtime = runtimes.json_rpc.handle().clone();

    // let sui-node signal main to shutdown runtimes
    let (runtime_shutdown_tx, runtime_shutdown_rx) = broadcast::channel::<()>(1);

    runtimes.sui_node.spawn(async move {
        match &config.health_check_config {
            Some(health_config) => {
                if health_config.enable.unwrap_or(false) == true {
                    let registry_service_clone = registry_service.clone();
                    tokio::spawn(async move {
                        sui_node::health_check::start_health_checks(registry_service_clone, notify, health_check_config).await;
                    });
                }
            },
            None => { info!("health check configed not enabled"); },
        }
        match sui_node::SuiNode::start_async(&config, registry_service, Some(rpc_runtime)).await {
            Ok(sui_node) => node_once_cell_clone
                .set(sui_node)
                .expect("Failed to set node in AsyncOnceCell"),

            Err(e) => {
                error!("Failed to start node: {e:?}");
                std::process::exit(1);
            }
        }

        // get node, subscribe to shutdown channel
        let node = node_once_cell_clone.get().await;
        let mut shutdown_rx = node.subscribe_to_shutdown_channel();

        // when we get a shutdown signal from sui-node, forward it on to the runtime_shutdown_channel here in
        // main to signal runtimes to all shutdown.
        tokio::select! {
           _ = shutdown_rx.recv() => {
                runtime_shutdown_tx.send(()).expect("failed to forward shutdown signal from sui-node to sui-node main");
            }
        }
        // TODO: Do we want to provide a way for the node to gracefully shutdown?
        loop {
            tokio::time::sleep(Duration::from_secs(1000)).await;
        }
    });

    let node_once_cell_clone = node_once_cell.clone();
    runtimes.metrics.spawn(async move {
        let node = node_once_cell_clone.get().await;
        let chain_identifier = match node.state().get_chain_identifier() {
            Some(chain_identifier) => chain_identifier.to_string(),
            None => "unknown".to_string(),
        };

        info!("Sui chain identifier: {chain_identifier}");
        prometheus_registry
            .register(mysten_metrics::uptime_metric(
                if is_validator {
                    "validator"
                } else {
                    "fullnode"
                },
                VERSION,
                chain_identifier.as_str(),
            ))
            .unwrap();

        sui_node::admin::run_admin_server(node, admin_interface_port, filter_handle).await
    });

    runtimes.metrics.spawn(async move {
        let node = node_once_cell.get().await;
        let state = node.state();
        loop {
            send_telemetry_event(state.clone(), is_validator).await;
            sleep(Duration::from_secs(3600)).await;
        }
    });

    // wait for SIGINT on the main thread
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(wait_termination(runtime_shutdown_rx));

    // Drop and wait all runtimes on main thread
    drop(runtimes);
}

#[cfg(not(unix))]
async fn wait_termination(mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = shutdown_rx.recv() => {},
    }
}

#[cfg(unix)]
async fn wait_termination(mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
    use futures::FutureExt;
    use tokio::signal::unix::*;

    let sigint = tokio::signal::ctrl_c().boxed();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let sigterm_recv = sigterm.recv().boxed();
    let shutdown_recv = shutdown_rx.recv().boxed();

    tokio::select! {
        _ = sigint => {},
        _ = sigterm_recv => {},
        _ = shutdown_recv => {},
    }
}
