use chrono::DateTime;
use ckb_build_info::Version;
use ckb_logger::info;
use ckb_network::{
    bytes::Bytes, CKBProtocol, CKBProtocolContext, CKBProtocolHandler, NetworkService,
    NetworkState, PeerIndex, MAX_FRAME_LENGTH_RELAY, MAX_FRAME_LENGTH_SYNC,
};
use ckb_sync::NetworkProtocol;
use ckb_types::{packed, prelude::*};
use ckb_util::{Condvar, Mutex};
use rasciigraph::{plot, Config as GraphConfig};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, HashMap};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    pub logger: ckb_logger::Config,
    pub network: ckb_network::NetworkConfig,
}

struct SyncMonitor;

impl CKBProtocolHandler for SyncMonitor {
    fn init(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>) {}

    fn connected(
        &mut self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer_index: PeerIndex,
        _version: &str,
    ) {
        if let Some(peer) = nc.get_peer(peer_index) {
            info!(
                "connected peer index: {}, connected_addr: {}, listened_addrs: {:?}, client_version: {}",
                peer_index, peer.connected_addr, peer.listened_addrs, peer.identify_info.map(|info| info.client_version).unwrap_or_default()
            );
        }
    }

    fn disconnected(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>, peer_index: PeerIndex) {
        info!("disconnected peer index: {}", peer_index);
    }
}

#[derive(Default)]
struct RelayMonitor {
    peers_counter: AtomicUsize,
}

impl CKBProtocolHandler for RelayMonitor {
    fn init(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>) {}

    fn received(
        &mut self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer_index: PeerIndex,
        data: Bytes,
    ) {
        let msg = match packed::RelayMessage::from_slice(&data) {
            Ok(msg) => msg.to_enum(),
            _ => {
                info!("peer {} sends us a malformed message", peer_index);
                nc.ban_peer(
                    peer_index,
                    Duration::from_secs(5 * 60),
                    String::from("send us a malformed message"),
                );
                return;
            }
        };

        match msg {
            packed::RelayMessageUnion::CompactBlock(compact_block) => {
                info!(
                    "compact_block: {:#x}, peers: {:?}",
                    compact_block.header().into_view().hash(),
                    self.peers_counter
                );
            }
            packed::RelayMessageUnion::RelayTransactionHashes(relay_transaction_hashes) => {
                relay_transaction_hashes
                    .tx_hashes()
                    .into_iter()
                    .for_each(|tx_hash| {
                        info!(
                            "relay_transaction_hashes: {:#x}, peers: {:?}",
                            tx_hash, self.peers_counter
                        );
                    })
            }
            _ => {}
        }
    }

    fn connected(
        &mut self,
        _nc: Arc<dyn CKBProtocolContext + Sync>,
        _peer_index: PeerIndex,
        _version: &str,
    ) {
        self.peers_counter.fetch_add(1, Ordering::SeqCst);
    }

    fn disconnected(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>, _peer_index: PeerIndex) {
        self.peers_counter.fetch_sub(1, Ordering::SeqCst);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut path = PathBuf::new();
    path.push(args.get(1).cloned().unwrap_or_else(|| ".".to_string()));

    if args.get(2) == Some(&"report".to_string()) {
        path.push("run.log");
        report(path);
    } else {
        path.push("config.toml");
        let mut config: Config =
            toml::from_slice(&std::fs::read(path.clone()).expect("can't find config file"))
                .unwrap();
        path.pop();
        path.push("run.log");
        config.logger.file = Some(path.clone());
        let _logger_guard = ckb_logger::init(config.logger).unwrap();
        path.pop();
        config.network.path = path;
        init_network(config.network);
    }
}

fn init_network(config: ckb_network::NetworkConfig) {
    let network_state =
        Arc::new(NetworkState::from_config(config).expect("Init network state failed"));
    let exit_condvar = Arc::new((Mutex::new(()), Condvar::new()));
    let required_protocol_ids = vec![NetworkProtocol::SYNC.into()];
    let version = get_version();

    let protocols = vec![
        CKBProtocol::new(
            "syn".to_string(),
            NetworkProtocol::SYNC.into(),
            &["1".to_string()][..],
            MAX_FRAME_LENGTH_SYNC,
            move || Box::new(SyncMonitor),
            Arc::clone(&network_state),
        ),
        CKBProtocol::new(
            "rel".to_string(),
            NetworkProtocol::RELAY.into(),
            &["1".to_string()][..],
            MAX_FRAME_LENGTH_RELAY,
            move || Box::new(RelayMonitor::default()),
            Arc::clone(&network_state),
        ),
    ];

    let _network_controller = NetworkService::new(
        Arc::clone(&network_state),
        protocols,
        required_protocol_ids,
        "/ckb/92b197aa".to_string(), // hardcoded mainnet hash
        version.to_string(),
        Arc::<(Mutex<()>, Condvar)>::clone(&exit_condvar),
    )
    .start(version, Some("NetworkService"))
    .expect("Start network service failed");

    wait_for_exit(exit_condvar);
}

fn report(log_file: PathBuf) {
    // 2020-03-10 17:02:23.239 +09:00 NetworkRuntime-0 INFO ckb-net-monitor  compact_block: 0x1ec85ed722ec6124e52a2f5d0dbdd73d33373ec7913033987d50035b62bab00d, peers: 67
    let re = Regex::new(r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} \+\d{2}:\d{2}).*(?P<message_type>compact_block|relay_transaction_hashes): 0x(?P<hash>[0-9a-f]{64}), peers: (?P<peers>.*)$").unwrap();

    let mut map: HashMap<String, (usize, String)> = HashMap::new();
    let mut result = Vec::new();

    for line in BufReader::new(File::open(log_file).expect("can't find log file")).lines() {
        if let Ok(l) = line {
            if let Some(captures) = re.captures(&l) {
                if "compact_block" == &captures["message_type"] {
                    if let Entry::Occupied(mut o) = map.entry(captures["hash"].to_owned()) {
                        let mut v = o.get_mut();
                        v.0 += 1;
                        let peers = usize::from_str_radix(&captures["peers"], 10).unwrap();
                        // 80% nodes, and >= 50 nodes samples, calculate the time duration
                        if v.0 * 10 >= peers * 8 && v.0 >= 50 {
                            let duration =
                                time_duration(&captures["timestamp"], &v.1) as f64 / 1000.0;
                            result.push(duration);
                            o.remove();
                            if result.len() >= 100 {
                                println!(
                                    "{}",
                                    plot(
                                        result,
                                        GraphConfig::default()
                                            .with_offset(5)
                                            .with_height(30)
                                            .with_caption(
                                                "Block 80% nodes propagation time ".to_string()
                                            )
                                    )
                                );
                                return;
                            }
                        }
                    } else {
                        map.insert(
                            captures["hash"].to_owned(),
                            (0, captures["timestamp"].to_owned()),
                        );
                    }
                }
            }
        }
    }
}

fn time_duration(t1: &str, t2: &str) -> i64 {
    DateTime::parse_from_str(t1, "%Y-%m-%d %H:%M:%S%.3f %z")
        .unwrap()
        .timestamp_millis()
        - DateTime::parse_from_str(t2, "%Y-%m-%d %H:%M:%S%.3f %z")
            .unwrap()
            .timestamp_millis()
}

fn get_version() -> Version {
    let major = env!("CARGO_PKG_VERSION_MAJOR")
        .parse::<u8>()
        .expect("CARGO_PKG_VERSION_MAJOR parse success");
    let minor = env!("CARGO_PKG_VERSION_MINOR")
        .parse::<u8>()
        .expect("CARGO_PKG_VERSION_MINOR parse success");
    let patch = env!("CARGO_PKG_VERSION_PATCH")
        .parse::<u16>()
        .expect("CARGO_PKG_VERSION_PATCH parse success");
    let dash_pre = {
        let pre = env!("CARGO_PKG_VERSION_PRE");
        if pre == "" {
            pre.to_string()
        } else {
            "-".to_string() + pre
        }
    };

    let commit_describe = option_env!("COMMIT_DESCRIBE").map(ToString::to_string);
    #[cfg(docker)]
    let commit_describe = commit_describe.map(|s| s.replace("-dirty", ""));
    let commit_date = option_env!("COMMIT_DATE").map(ToString::to_string);
    let code_name = None;
    Version {
        major,
        minor,
        patch,
        dash_pre,
        code_name,
        commit_describe,
        commit_date,
    }
}

fn wait_for_exit(exit: Arc<(Mutex<()>, Condvar)>) {
    // Handle possible exits
    let e = Arc::<(Mutex<()>, Condvar)>::clone(&exit);
    let _ = ctrlc::set_handler(move || {
        e.1.notify_all();
    });

    // Wait for signal
    let mut l = exit.0.lock();
    exit.1.wait(&mut l);
}
