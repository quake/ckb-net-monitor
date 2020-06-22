use chrono::DateTime;
use ckb_build_info::Version;
use ckb_logger::{error, info, metric};
use ckb_network::{
    bytes::Bytes, BlockingFlag, CKBProtocol, CKBProtocolContext, CKBProtocolHandler,
    NetworkService, NetworkState, PeerIndex, MAX_FRAME_LENGTH_RELAY, MAX_FRAME_LENGTH_SYNC,
};
use ckb_sync::NetworkProtocol;
use ckb_types::packed::Byte32;
use ckb_types::{core, packed, prelude::*};
use ckb_util::{Condvar, Mutex, RwLock};
use rasciigraph::{plot, Config as GraphConfig};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, HashMap};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const PRINT_LATENCY_INTERVAL: Duration = Duration::from_secs(20);
pub const PRINT_LATENCY_TOKEN: u64 = 11111;
pub const PRINT_LATENCY_COUNT: u64 = 10;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    pub logger: ckb_logger::Config,
    pub network: ckb_network::NetworkConfig,
}

struct PeerState {
    headers: HashMap<Byte32, core::HeaderView>,
    in_flight_blocks: HashMap<Byte32, Instant>, // block_hash => the timestamp sent request
    arrived_blocks: HashMap<Byte32, Duration>,  // block_hash => the latency received response
}

struct MonitorHandler {
    peers: Arc<RwLock<HashMap<PeerIndex, PeerState>>>,
}

impl Default for PeerState {
    fn default() -> Self {
        Self {
            headers: Default::default(),
            in_flight_blocks: Default::default(),
            arrived_blocks: Default::default(),
        }
    }
}

impl Default for MonitorHandler {
    fn default() -> Self {
        Self {
            peers: Arc::new(RwLock::new(Default::default())),
        }
    }
}

impl Clone for MonitorHandler {
    fn clone(&self) -> Self {
        Self {
            peers: Arc::clone(&self.peers),
        }
    }
}

impl CKBProtocolHandler for MonitorHandler {
    fn init(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>) {
        if nc.protocol_id() == NetworkProtocol::SYNC.into() {
            nc.set_notify(PRINT_LATENCY_INTERVAL, PRINT_LATENCY_TOKEN)
                .expect("set_notify PRINT_LATENCY_TOKEN");
        }
    }

    fn connected(
        &mut self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer_index: PeerIndex,
        _version: &str,
    ) {
        let mut peers = self.peers.write();
        if peers.contains_key(&peer_index) {
            return;
        }

        if let Some(peer) = nc.get_peer(peer_index) {
            peers.insert(peer_index, Default::default());

            info!(
                "connected peer index: {}, connected_addr: {}, listened_addrs: {:?}, client_version: {}",
                peer_index, peer.connected_addr, peer.listened_addrs, peer.identify_info.map(|info| info.client_version).unwrap_or_default()
            );
        }
    }

    fn disconnected(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>, peer_index: PeerIndex) {
        self.peers.write().remove(&peer_index);
        info!("disconnected peer index: {}", peer_index);
    }

    fn received(
        &mut self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer_index: PeerIndex,
        data: Bytes,
    ) {
        if let Ok(msg) = packed::SyncMessage::from_slice(&data) {
            self.received_sync_message(nc, peer_index, msg.to_enum());
        } else if let Ok(msg) = packed::RelayMessage::from_slice(&data) {
            self.received_relay_message(nc, peer_index, msg.to_enum());
        } else {
            error!("peer {} sends us a malformed message", peer_index);
            nc.ban_peer(
                peer_index,
                Duration::from_secs(5 * 60),
                String::from("send us a malformed message"),
            );
        }
    }

    fn notify(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>, token: u64) {
        assert_eq!(token, PRINT_LATENCY_TOKEN);

        let mut peers = self.peers.write();
        let mut outputs = HashMap::new();
        for (peer_index, state) in peers.iter_mut() {
            let mut latencies = HashMap::<u64, u64>::new();
            let headers = &state.headers;
            for (block_hash, _) in state.in_flight_blocks.iter() {
                let header = headers.get(block_hash).unwrap();
                latencies.insert(header.number(), u64::max_value());
            }
            for (block_hash, latency) in state.arrived_blocks.iter() {
                let header = headers.get(block_hash).unwrap();
                latencies.insert(header.number(), latency.as_millis() as u64);
            }

            let mut latencies = latencies.into_iter().collect::<Vec<_>>();
            latencies.sort_by_key(|(number, _latency)| *number);
            outputs.insert(peer_index.value(), latencies);
        }
        info!("latency: {:?}", outputs);

        for (peer_index, state) in peers.iter_mut() {
            state.arrived_blocks.clear();
            state.in_flight_blocks.clear();
            if state.headers.len() > PRINT_LATENCY_COUNT as usize {
                let tip_number = state
                    .headers
                    .iter()
                    .map(|(_, header)| header.number())
                    .max()
                    .unwrap_or(0);
                state.headers.retain(|_, header| {
                    header.number() > tip_number.saturating_sub(PRINT_LATENCY_COUNT)
                });
            }

            let hashes = state
                .headers
                .iter()
                .map(|(_, header)| header.hash())
                .collect::<Vec<_>>();
            self.send_getblocks(&nc, *peer_index, hashes);
            let now = Instant::now();
            for (block_hash, _) in state.headers.iter() {
                state.in_flight_blocks.insert(block_hash.clone(), now);
            }
        }
    }
}

impl MonitorHandler {
    #[allow(clippy::single_match)]
    fn received_sync_message(
        &mut self,
        _nc: Arc<dyn CKBProtocolContext + Sync>,
        peer_index: PeerIndex,
        message: packed::SyncMessageUnion,
    ) {
        let mut peers = self.peers.write();
        let state = peers.get_mut(&peer_index).expect("connected peer exist");

        match message {
            packed::SyncMessageUnion::SendBlock(block) => {
                let block_hash = block.block().header().into_view().hash();
                if let Some(timestamp) = state.in_flight_blocks.remove(&block_hash) {
                    let latency = timestamp.elapsed();
                    state.arrived_blocks.insert(block_hash, latency);
                }
            }
            _ => {}
        }
    }

    fn received_relay_message(
        &mut self,
        _nc: Arc<dyn CKBProtocolContext + Sync>,
        peer_index: PeerIndex,
        message: packed::RelayMessageUnion,
    ) {
        let total_peers = self.peers.read().len();
        match message {
            packed::RelayMessageUnion::CompactBlock(compact_block) => {
                info!(
                    "compact_block: {:#x}, peers: {:?}",
                    compact_block.header().into_view().hash(),
                    total_peers,
                );
                let header = compact_block.header().into_view();
                let block_hash = header.hash();
                metric!({
                    "topic": "propagation",
                    "tags": { "compact_block": format!("{}", block_hash) },
                    "fields": { "total_peers": total_peers },
                });

                // We want to collect the latency between peers.
                let mut peers = self.peers.write();
                let state = peers.get_mut(&peer_index).expect("connected peer exist");
                state.headers.insert(block_hash, header);
            }
            packed::RelayMessageUnion::RelayTransactionHashes(relay_transaction_hashes) => {
                relay_transaction_hashes
                    .tx_hashes()
                    .into_iter()
                    .for_each(|tx_hash| {
                        info!(
                            "relay_transaction_hashes: {:#x}, peers: {:?}",
                            tx_hash, total_peers,
                        );
                    })
            }
            _ => {}
        }
    }

    fn send_getblocks(
        &self,
        nc: &Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        hashes: Vec<Byte32>,
    ) {
        let content = packed::GetBlocks::new_builder()
            .block_hashes(hashes.pack())
            .build();
        let message = packed::SyncMessage::new_builder().set(content).build();
        if let Err(err) = nc.send_message(NetworkProtocol::SYNC.into(), peer, message.as_bytes()) {
            error!("send_getblock to {} error: {:?}", peer, err);
        }
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

    let monitor = MonitorHandler::default();
    let monitor_clone = monitor.clone();

    let protocols = vec![
        CKBProtocol::new(
            "syn".to_string(),
            NetworkProtocol::SYNC.into(),
            &["1".to_string()][..],
            MAX_FRAME_LENGTH_SYNC,
            move || Box::new(monitor.clone()),
            Arc::clone(&network_state),
            BlockingFlag::default(),
        ),
        CKBProtocol::new(
            "rel".to_string(),
            NetworkProtocol::RELAY.into(),
            &["1".to_string()][..],
            MAX_FRAME_LENGTH_RELAY,
            move || Box::new(monitor_clone.clone()),
            Arc::clone(&network_state),
            BlockingFlag::default(),
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
