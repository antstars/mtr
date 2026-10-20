use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use dns_lookup::lookup_addr;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
    Frame, Terminal,
};
use std::{
    collections::{HashMap, HashSet},
    io,
    io::Write,
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc::{self, Receiver, Sender, SyncSender},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const DEFAULT_REPORT_CYCLES: u32 = 10;
const DEFAULT_PROBE_INTERVAL_SECONDS: f64 = 1.0;

const MAXIMUM_ROUTE_HOPS: u8 = 30;
const MAXIMUM_SUPPORTED_HOPS: u8 = 64;
const PROBE_TIMEOUT: Duration = Duration::from_millis(800);
const NETWORK_EVENT_CAPACITY: usize = 256;

// ============================================================================
// 终端会话守卫 (RAII)
// 为什么：防止进程在发生 Panic 或中途异常退出时，使得用户的终端界面卡死或排版错乱
// ============================================================================
struct TerminalSession {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalSession {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut standard_output = io::stdout();
        execute!(standard_output, EnterAlternateScreen)?;
        let tui_backend = CrosstermBackend::new(standard_output);
        let terminal = Terminal::new(tui_backend)?;
        Ok(Self { terminal })
    }

    fn terminal_mut(&mut self) -> &mut Terminal<CrosstermBackend<io::Stdout>> {
        &mut self.terminal
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

// ============================================================================
// 领域模型与核心数据结构
// ============================================================================
#[derive(Parser, Debug)]
#[command(name = "Rust MTR")]
#[command(version)]
#[command(about = "A cross-platform concurrent network diagnostic tool written in Rust", long_about = None)]
pub struct CliArgs {
    #[arg(required = true)]
    pub target: String,
    #[arg(short = 'r', long)]
    pub report: bool,
    #[arg(short = 'c', long, value_name = "COUNT", requires = "report")]
    pub report_cycles: Option<u32>,
    #[arg(short = 'i', long, value_name = "SECONDS", default_value_t = DEFAULT_PROBE_INTERVAL_SECONDS)]
    pub interval: f64,
    #[arg(short = 'n', long)]
    pub no_dns: bool,
    #[arg(short = '4', long, conflicts_with = "ipv6")]
    pub ipv4: bool,
    #[arg(short = '6', long, conflicts_with = "ipv4")]
    pub ipv6: bool,
    #[arg(short = 'm', long, default_value_t = MAXIMUM_ROUTE_HOPS)]
    pub max_hops: u8,
}

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub report: bool,
    pub report_cycles: u32,
    pub interval: Duration,
    pub no_dns: bool,
    pub max_hops: u8,
}

impl ProbeConfig {
    fn from_args(args: &CliArgs) -> Result<Self, String> {
        if !args.interval.is_finite() || args.interval < PROBE_TIMEOUT.as_secs_f64() {
            return Err(format!(
                "interval must be at least {:.1} seconds",
                PROBE_TIMEOUT.as_secs_f64()
            ));
        }
        if args.max_hops == 0 || args.max_hops > MAXIMUM_SUPPORTED_HOPS {
            return Err(format!(
                "max-hops must be between 1 and {}",
                MAXIMUM_SUPPORTED_HOPS
            ));
        }
        if args.ipv4 && args.target.parse::<std::net::Ipv6Addr>().is_ok() {
            return Err(String::from("--ipv4 requires an IPv4 target"));
        }
        let report_cycles = args.report_cycles.unwrap_or(DEFAULT_REPORT_CYCLES);
        if report_cycles == 0 {
            return Err(String::from("report-cycles must be greater than zero"));
        }
        let interval = Duration::try_from_secs_f64(args.interval)
            .map_err(|_| String::from("interval is outside the supported range"))?;
        if interval < PROBE_TIMEOUT {
            return Err(format!(
                "interval must be at least {:.1} seconds",
                PROBE_TIMEOUT.as_secs_f64()
            ));
        }

        Ok(Self {
            report: args.report,
            report_cycles,
            interval,
            no_dns: args.no_dns,
            max_hops: args.max_hops,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HopStatistic {
    pub ttl: u8,
    pub ip_address: Option<IpAddr>,
    pub packets_sent: u32,
    pub packets_received: u32,
    pub last_latency_ms: Option<f64>,
    pub best_latency_ms: Option<f64>,
    pub worst_latency_ms: Option<f64>,
    pub mean_latency_ms: f64,
    pub m2_latency_ms: f64,
}

impl HopStatistic {
    pub fn new(ttl: u8, ip_address: Option<IpAddr>) -> Self {
        Self {
            ttl,
            ip_address,
            packets_sent: 0,
            packets_received: 0,
            last_latency_ms: None,
            best_latency_ms: None,
            worst_latency_ms: None,
            mean_latency_ms: 0.0,
            m2_latency_ms: 0.0,
        }
    }

    pub fn reset_statistics(&mut self) {
        self.packets_sent = 0;
        self.packets_received = 0;
        self.last_latency_ms = None;
        self.best_latency_ms = None;
        self.worst_latency_ms = None;
        self.mean_latency_ms = 0.0;
        self.m2_latency_ms = 0.0;
    }

    pub fn packet_loss_percentage(&self) -> f64 {
        if self.packets_sent == 0 {
            return 0.0;
        }
        let lost_packets = self.packets_sent.saturating_sub(self.packets_received);
        (lost_packets as f64 / self.packets_sent as f64) * 100.0
    }

    pub fn average_latency_ms(&self) -> Option<f64> {
        if self.packets_received == 0 {
            return None;
        }
        Some(self.mean_latency_ms)
    }

    pub fn standard_deviation(&self) -> Option<f64> {
        if self.packets_received < 2 {
            return None;
        }
        let variance = self.m2_latency_ms / ((self.packets_received - 1) as f64);
        Some(variance.sqrt())
    }

    pub fn record_probe_result(&mut self, latency_ms: Option<f64>) {
        self.packets_sent = self.packets_sent.saturating_add(1);

        if let Some(latency_value_ms) = latency_ms {
            self.packets_received = self.packets_received.saturating_add(1);
            self.last_latency_ms = Some(latency_value_ms);

            self.best_latency_ms = Some(match self.best_latency_ms {
                Some(current_best_ms) => current_best_ms.min(latency_value_ms),
                None => latency_value_ms,
            });

            self.worst_latency_ms = Some(match self.worst_latency_ms {
                Some(current_worst_ms) => current_worst_ms.max(latency_value_ms),
                None => latency_value_ms,
            });

            // 为什么：使用 Welford 在线算法，避免 IEEE 754 浮点数在计算平方和差值时发生灾难性取消
            let delta = latency_value_ms - self.mean_latency_ms;
            self.mean_latency_ms += delta / (self.packets_received as f64);
            let delta2 = latency_value_ms - self.mean_latency_ms;
            self.m2_latency_ms += delta * delta2;
        }
    }
}

pub enum NetworkEvent {
    RouteHopDiscovered {
        ttl: u8,
        ip_address: IpAddr,
    },
    EchoProbeResult {
        ttl: u8,
        latency_ms: Option<f64>,
        reached_target: bool,
    },
    ProbeCycleComplete,
    ProbeError {
        message: String,
        suggest_capability: bool,
    },
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum NetworkStatus {
    Ready,
    Reduced {
        capability_command: Option<String>,
    },
    Unavailable {
        details: String,
        capability_command: Option<String>,
    },
}

#[cfg(target_os = "linux")]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(target_os = "linux")]
fn capability_command() -> Option<String> {
    let executable_path = std::env::current_exe()
        .ok()
        .and_then(|path| path.into_os_string().into_string().ok())?;
    if contains_unsafe_display_characters(&executable_path) {
        return None;
    }
    Some(format!(
        "sudo setcap cap_net_raw+ep {}",
        shell_quote(&executable_path)
    ))
}

#[cfg(not(target_os = "linux"))]
fn capability_command() -> Option<String> {
    None
}

#[cfg(windows)]
fn windows_network_status() -> NetworkStatus {
    use windows_sys::Win32::NetworkManagement::IpHelper::{IcmpCloseHandle, IcmpCreateFile};

    // SAFETY: IcmpCreateFile receives no pointers and returns an opaque handle;
    // every successful handle is closed before this function returns.
    unsafe {
        let handle = IcmpCreateFile();
        if handle == 0 || handle == (-1isize) as _ {
            NetworkStatus::Unavailable {
                details: format!(
                    "Windows IcmpCreateFile failed: {}",
                    std::io::Error::last_os_error()
                ),
                capability_command: None,
            }
        } else {
            // The handle is owned exclusively here and is released before returning.
            let _ = IcmpCloseHandle(handle);
            NetworkStatus::Ready
        }
    }
}

pub struct DnsResolvedEvent {
    pub original_ip: IpAddr,
    pub resolved_hostname: String,
}

// ============================================================================
// 底层网络引擎 - Windows 实现（常驻 1-to-1 线程矩阵）
// 为什么：IcmpSendEcho 是阻塞调用，若共用少量的线程池，当遇到多个禁 Ping 节点时会引发
// 管线阻塞 (Pipeline Stall)，导致整体探测周期从 1 秒被拉长至数秒。
// ============================================================================
#[cfg(windows)]
pub struct ActiveNetworkProber;

#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
struct WindowsProbeTask {
    ttl: u8,
    target_ipv4: Ipv4Addr,
    probe_timeout_ms: u32,
}

#[cfg(windows)]
impl ActiveNetworkProber {
    pub fn spawn(
        event_transmitter: SyncSender<NetworkEvent>,
        target_ipv4: Ipv4Addr,
        is_paused: Arc<AtomicBool>,
        should_exit: Arc<AtomicBool>,
        config: ProbeConfig,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            let maximum_route_hops = config.max_hops;
            let probe_timeout_ms = PROBE_TIMEOUT.as_millis() as u32;
            let dynamic_max_ttl = Arc::new(AtomicU8::new(maximum_route_hops));

            let mut ttl_senders: Vec<Sender<WindowsProbeTask>> =
                Vec::with_capacity(maximum_route_hops as usize);
            let mut worker_join_handles: Vec<JoinHandle<()>> =
                Vec::with_capacity(maximum_route_hops as usize);
            let mut completed_cycles = 0u32;

            for _ in 0..maximum_route_hops {
                let (task_sender, task_receiver) = mpsc::channel::<WindowsProbeTask>();
                ttl_senders.push(task_sender);

                let worker_event_transmitter = event_transmitter.clone();
                let worker_should_exit = Arc::clone(&should_exit);
                let worker_dynamic_max_ttl = Arc::clone(&dynamic_max_ttl);

                let join_handle = thread::spawn(move || {
                    Self::run_windows_probe_worker(
                        task_receiver,
                        worker_event_transmitter,
                        worker_dynamic_max_ttl,
                        worker_should_exit,
                    );
                });
                worker_join_handles.push(join_handle);
            }

            while !should_exit.load(Ordering::Relaxed) {
                if is_paused.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }

                let current_limit = dynamic_max_ttl.load(Ordering::Relaxed);

                for ttl in 1..=current_limit {
                    if should_exit.load(Ordering::Relaxed) {
                        break;
                    }

                    let probe_task = WindowsProbeTask {
                        ttl,
                        target_ipv4,
                        probe_timeout_ms,
                    };

                    let worker_index = (ttl - 1) as usize;
                    let _ = ttl_senders[worker_index].send(probe_task);
                }

                let sleep_start_time = Instant::now();
                while sleep_start_time.elapsed() < config.interval {
                    if should_exit.load(Ordering::Relaxed) || is_paused.load(Ordering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                let _ = event_transmitter.send(NetworkEvent::ProbeCycleComplete);
                completed_cycles = completed_cycles.saturating_add(1);
                if config.report && completed_cycles >= config.report_cycles {
                    break;
                }
            }

            drop(ttl_senders);
            for join_handle in worker_join_handles {
                let _ = join_handle.join();
            }
        })
    }

    fn run_windows_probe_worker(
        task_receiver: Receiver<WindowsProbeTask>,
        event_transmitter: SyncSender<NetworkEvent>,
        dynamic_max_ttl: Arc<AtomicU8>,
        should_exit: Arc<AtomicBool>,
    ) {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY, IP_OPTION_INFORMATION,
        };

        const IP_TTL_EXPIRED_TRANSIT_STATUS: u32 = 11013;

        while !should_exit.load(Ordering::Relaxed) {
            let probe_task = match task_receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(task) => task,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };

            unsafe {
                let icmp_handle = IcmpCreateFile();
                if icmp_handle == 0 || icmp_handle == (-1isize) as _ {
                    continue;
                }

                let destination_address = u32::from_ne_bytes(probe_task.target_ipv4.octets());
                let probe_payload = b"RUST_MTR_PROBE";
                let reply_buffer_size: usize = 1024;
                let mut reply_buffer = vec![0u8; reply_buffer_size];

                let ip_options = IP_OPTION_INFORMATION {
                    Ttl: probe_task.ttl,
                    Tos: 0,
                    Flags: 0,
                    OptionsSize: 0,
                    OptionsData: std::ptr::null_mut(),
                };

                let result_count = IcmpSendEcho(
                    icmp_handle,
                    destination_address,
                    probe_payload.as_ptr() as _,
                    probe_payload.len() as u16,
                    &ip_options,
                    reply_buffer.as_mut_ptr() as _,
                    reply_buffer_size as u32,
                    probe_task.probe_timeout_ms,
                );

                if result_count > 0 {
                    let icmp_reply = &*(reply_buffer.as_ptr() as *const ICMP_ECHO_REPLY);
                    let router_ipv4 = Ipv4Addr::from(icmp_reply.Address.to_ne_bytes());
                    let latency_ms = icmp_reply.RoundTripTime as f64;
                    let status_code = icmp_reply.Status;

                    if icmp_reply.Address != 0 {
                        let _ = event_transmitter.send(NetworkEvent::RouteHopDiscovered {
                            ttl: probe_task.ttl,
                            ip_address: IpAddr::V4(router_ipv4),
                        });
                    }

                    let is_success = status_code == 0;
                    let is_transit = status_code == IP_TTL_EXPIRED_TRANSIT_STATUS;
                    let reached_target = is_success && router_ipv4 == probe_task.target_ipv4;

                    if is_success || is_transit {
                        let _ = event_transmitter.send(NetworkEvent::EchoProbeResult {
                            ttl: probe_task.ttl,
                            latency_ms: Some(latency_ms),
                            reached_target,
                        });

                        if reached_target {
                            dynamic_max_ttl.fetch_min(probe_task.ttl, Ordering::Relaxed);
                        }
                    } else {
                        let _ = event_transmitter.send(NetworkEvent::EchoProbeResult {
                            ttl: probe_task.ttl,
                            latency_ms: None,
                            reached_target: false,
                        });
                    }
                } else {
                    let _ = event_transmitter.send(NetworkEvent::EchoProbeResult {
                        ttl: probe_task.ttl,
                        latency_ms: None,
                        reached_target: false,
                    });
                }

                IcmpCloseHandle(icmp_handle);
            }
        }
    }
}

#[cfg(unix)]
pub struct ActiveIpv6NetworkProber;

#[cfg(unix)]
impl ActiveIpv6NetworkProber {
    pub fn spawn(
        event_transmitter: SyncSender<NetworkEvent>,
        target_ipv6: std::net::Ipv6Addr,
        is_paused: Arc<AtomicBool>,
        should_exit: Arc<AtomicBool>,
        config: ProbeConfig,
    ) -> JoinHandle<()> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::net::{SocketAddr, SocketAddrV6};

        thread::spawn(move || {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))
                .map(|socket| (socket, SocketKind::Datagram))
                .or_else(|_| {
                    Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
                        .map(|socket| (socket, SocketKind::Raw))
                });
            let (socket, socket_kind) = match socket {
                Ok(socket) => socket,
                Err(error) => {
                    let _ = event_transmitter.send(NetworkEvent::ProbeError {
                        message: error.to_string(),
                        suggest_capability: true,
                    });
                    return;
                }
            };
            if matches!(socket_kind, SocketKind::Raw) {
                let _ = event_transmitter.send(NetworkEvent::ProbeError {
                    message: String::from(
                        "raw ICMPv6 requires pseudo-header checksum support; use an ICMPv6 datagram socket",
                    ),
                    suggest_capability: false,
                });
                return;
            }
            if let Err(error) = socket.set_read_timeout(Some(Duration::from_millis(10))) {
                let _ = event_transmitter.send(NetworkEvent::ProbeError {
                    message: error.to_string(),
                    suggest_capability: false,
                });
                return;
            }

            let target_addr = SocketAddr::V6(SocketAddrV6::new(target_ipv6, 0, 0, 0));
            let process_identifier = std::process::id() as u16;
            let mut sequence_number = 0u16;
            let mut completed_cycles = 0u32;
            let dynamic_max_ttl = Arc::new(AtomicU8::new(config.max_hops));

            while !should_exit.load(Ordering::Relaxed) {
                if is_paused.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                let start_time = Instant::now();
                let mut in_flight = HashMap::new();
                let current_limit = dynamic_max_ttl.load(Ordering::Relaxed);
                let mut successful_sends = 0u32;
                let mut last_send_error = None;
                for ttl in 1..=current_limit {
                    sequence_number = sequence_number.wrapping_add(1);
                    let packet = build_ipv6_echo_request(sequence_number, process_identifier);
                    match socket.set_unicast_hops_v6(ttl as u32) {
                        Ok(()) => match socket.send_to(&packet, &target_addr.into()) {
                            Ok(_) => {
                                successful_sends += 1;
                                in_flight.insert(sequence_number, (ttl, Instant::now()));
                            }
                            Err(error) => last_send_error = Some(error),
                        },
                        Err(error) => last_send_error = Some(error),
                    }
                }
                if successful_sends == 0 {
                    let _ = event_transmitter.send(NetworkEvent::ProbeError {
                        message: format!(
                            "unable to send ICMPv6 probe: {}",
                            last_send_error
                                .map(|error| error.to_string())
                                .unwrap_or_else(|| String::from("unknown socket error"))
                        ),
                        suggest_capability: false,
                    });
                    return;
                }

                let mut buffer = [std::mem::MaybeUninit::uninit(); 2048];
                while start_time.elapsed() < PROBE_TIMEOUT && !should_exit.load(Ordering::Relaxed) {
                    if let Ok((bytes_read, address)) = socket.recv_from(&mut buffer) {
                        let source_ip = match address.as_socket_ipv6() {
                            Some(address) => IpAddr::V6(*address.ip()),
                            None => continue,
                        };
                        // SAFETY: recv_from reports the initialized prefix length and the
                        // socket API guarantees bytes_read does not exceed the buffer size.
                        let packet_data = unsafe {
                            std::slice::from_raw_parts(buffer.as_ptr() as *const u8, bytes_read)
                        };
                        if let Some(metadata) = extract_ipv6_probe_metadata(packet_data) {
                            if matches!(socket_kind, SocketKind::Raw)
                                && metadata.process_identifier != process_identifier
                            {
                                continue;
                            }
                            if let Some((ttl, sent_time)) =
                                in_flight.remove(&metadata.sequence_number)
                            {
                                let reached_target =
                                    matches!(metadata.response_type, IcmpResponseType::EchoReply);
                                let _ = event_transmitter.send(NetworkEvent::RouteHopDiscovered {
                                    ttl,
                                    ip_address: source_ip,
                                });
                                let _ = event_transmitter.send(NetworkEvent::EchoProbeResult {
                                    ttl,
                                    latency_ms: Some(sent_time.elapsed().as_secs_f64() * 1000.0),
                                    reached_target,
                                });
                                if reached_target {
                                    dynamic_max_ttl.fetch_min(ttl, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
                for (ttl, _) in in_flight.values() {
                    let _ = event_transmitter.send(NetworkEvent::EchoProbeResult {
                        ttl: *ttl,
                        latency_ms: None,
                        reached_target: false,
                    });
                }
                while start_time.elapsed() < config.interval {
                    if should_exit.load(Ordering::Relaxed) || is_paused.load(Ordering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                let _ = event_transmitter.send(NetworkEvent::ProbeCycleComplete);
                completed_cycles = completed_cycles.saturating_add(1);
                if config.report && completed_cycles >= config.report_cycles {
                    break;
                }
            }
        })
    }
}

// ============================================================================
// 底层网络引擎 - Unix (Linux/macOS) 实现
// ============================================================================
#[cfg(unix)]
enum IcmpResponseType {
    EchoReply,
    TimeExceeded,
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum SocketKind {
    Raw,
    Datagram,
}

#[cfg(unix)]
struct IcmpMatchMetadata {
    pub response_type: IcmpResponseType,
    pub process_identifier: u16,
    pub sequence_number: u16,
}

#[cfg(unix)]
#[allow(dead_code)]
fn extract_ipv6_probe_metadata(packet_data: &[u8]) -> Option<IcmpMatchMetadata> {
    const IPV6_HEADER_LENGTH: usize = 40;
    const ICMPV6_HEADER_LENGTH: usize = 8;

    let icmp_offset = if packet_data.len() >= IPV6_HEADER_LENGTH && packet_data[0] >> 4 == 6 {
        if packet_data[6] != 58 {
            return None;
        }
        IPV6_HEADER_LENGTH
    } else {
        0
    };

    if packet_data.len() < icmp_offset + ICMPV6_HEADER_LENGTH {
        return None;
    }

    match packet_data[icmp_offset] {
        129 => {
            if packet_data[icmp_offset + 1] != 0 {
                return None;
            }
            Some(IcmpMatchMetadata {
                response_type: IcmpResponseType::EchoReply,
                process_identifier: u16::from_be_bytes([
                    packet_data[icmp_offset + 4],
                    packet_data[icmp_offset + 5],
                ]),
                sequence_number: u16::from_be_bytes([
                    packet_data[icmp_offset + 6],
                    packet_data[icmp_offset + 7],
                ]),
            })
        }
        3 => {
            if packet_data[icmp_offset + 1] > 1 {
                return None;
            }
            let embedded_ipv6_offset = icmp_offset + ICMPV6_HEADER_LENGTH;
            let embedded_icmp_offset = embedded_ipv6_offset + IPV6_HEADER_LENGTH;
            if packet_data.len() < embedded_icmp_offset + ICMPV6_HEADER_LENGTH
                || packet_data[embedded_ipv6_offset] >> 4 != 6
                || packet_data[embedded_ipv6_offset + 6] != 58
                || packet_data[embedded_icmp_offset] != 128
            {
                return None;
            }
            Some(IcmpMatchMetadata {
                response_type: IcmpResponseType::TimeExceeded,
                process_identifier: u16::from_be_bytes([
                    packet_data[embedded_icmp_offset + 4],
                    packet_data[embedded_icmp_offset + 5],
                ]),
                sequence_number: u16::from_be_bytes([
                    packet_data[embedded_icmp_offset + 6],
                    packet_data[embedded_icmp_offset + 7],
                ]),
            })
        }
        _ => None,
    }
}

#[cfg(unix)]
#[allow(dead_code)]
fn build_ipv6_echo_request(sequence_number: u16, process_identifier: u16) -> [u8; 8] {
    // ICMPv6 checksum is filled by the kernel for the planned SOCK_DGRAM path;
    // raw-socket integration must replace this builder with pseudo-header checksum handling.
    let mut packet = [0u8; 8];
    packet[0] = 128;
    packet[4..6].copy_from_slice(&process_identifier.to_be_bytes());
    packet[6..8].copy_from_slice(&sequence_number.to_be_bytes());
    packet
}

#[cfg(unix)]
pub struct ActiveNetworkProber;

#[cfg(unix)]
impl ActiveNetworkProber {
    pub fn spawn(
        event_transmitter: SyncSender<NetworkEvent>,
        target_ipv4: Ipv4Addr,
        is_paused: Arc<AtomicBool>,
        should_exit: Arc<AtomicBool>,
        config: ProbeConfig,
    ) -> JoinHandle<()> {
        use std::net::SocketAddr;

        thread::spawn(move || {
            let (socket, socket_kind) = match Self::create_icmp_socket() {
                Ok(socket_instance) => socket_instance,
                Err(error) => {
                    eprintln!("❌ 无法创建 ICMP 探测 socket。");
                    eprintln!("系统报错: {}", error);
                    eprintln!("Linux: run install.sh to grant cap_net_raw; SUID is not supported.");
                    eprintln!("macOS: run with an account allowed to create ICMP sockets.");
                    let _ = event_transmitter.send(NetworkEvent::ProbeError {
                        message: error.to_string(),
                        suggest_capability: true,
                    });
                    return;
                }
            };

            if let Err(error) = socket.set_read_timeout(Some(Duration::from_millis(10))) {
                eprintln!("❌ 致命错误: 无法设置 Raw Socket 读超时。");
                eprintln!("系统报错: {}", error);
                let _ = event_transmitter.send(NetworkEvent::ProbeError {
                    message: error.to_string(),
                    suggest_capability: false,
                });
                return;
            }

            let target_addr = SocketAddr::from((target_ipv4, 0));
            let process_identifier = std::process::id() as u16;
            let maximum_route_hops = config.max_hops;
            let dynamic_max_ttl = Arc::new(AtomicU8::new(maximum_route_hops));
            let mut sequence_number: u16 = 0;
            let mut completed_cycles = 0u32;

            while !should_exit.load(Ordering::Relaxed) {
                if is_paused.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }

                let current_limit = dynamic_max_ttl.load(Ordering::Relaxed);
                let start_time = Instant::now();
                let mut in_flight_probes: HashMap<u16, (u8, Instant)> = HashMap::new();

                for ttl in 1..=current_limit {
                    if should_exit.load(Ordering::Relaxed) {
                        break;
                    }

                    sequence_number = sequence_number.wrapping_add(1);
                    let packet = Self::build_echo_request(sequence_number, process_identifier);

                    if socket.set_ttl(ttl as u32).is_ok()
                        && socket.send_to(&packet, &target_addr.into()).is_ok()
                    {
                        in_flight_probes.insert(sequence_number, (ttl, Instant::now()));
                    }
                }

                let mut buffer = [std::mem::MaybeUninit::uninit(); 1024];
                let gather_window = PROBE_TIMEOUT;

                while start_time.elapsed() < gather_window && !should_exit.load(Ordering::Relaxed) {
                    if let Ok((bytes_read, addr)) = socket.recv_from(&mut buffer) {
                        let source_ip = match addr.as_socket_ipv4() {
                            Some(v4_socket_addr) => *v4_socket_addr.ip(),
                            None => continue,
                        };

                        let packet_data: &[u8] = unsafe {
                            std::slice::from_raw_parts(buffer.as_ptr() as *const u8, bytes_read)
                        };

                        if let Some(metadata) =
                            Self::extract_probe_metadata(packet_data, socket_kind)
                        {
                            if matches!(socket_kind, SocketKind::Raw)
                                && metadata.process_identifier != process_identifier
                            {
                                continue;
                            }

                            if let Some((ttl, sent_time)) =
                                in_flight_probes.remove(&metadata.sequence_number)
                            {
                                let latency_ms = sent_time.elapsed().as_secs_f64() * 1000.0;
                                let reached_target =
                                    matches!(metadata.response_type, IcmpResponseType::EchoReply);

                                let _ = event_transmitter.send(NetworkEvent::RouteHopDiscovered {
                                    ttl,
                                    ip_address: IpAddr::V4(source_ip),
                                });

                                let _ = event_transmitter.send(NetworkEvent::EchoProbeResult {
                                    ttl,
                                    latency_ms: Some(latency_ms),
                                    reached_target,
                                });

                                if reached_target {
                                    dynamic_max_ttl.fetch_min(ttl, Ordering::Relaxed);
                                    break;
                                }
                            }
                        }
                    }
                }

                for (_, (ttl, _)) in in_flight_probes {
                    let _ = event_transmitter.send(NetworkEvent::EchoProbeResult {
                        ttl,
                        latency_ms: None,
                        reached_target: false,
                    });
                }

                let elapsed = start_time.elapsed();
                let probe_interval = config.interval;
                let sleep_start_time = Instant::now();
                while elapsed + sleep_start_time.elapsed() < probe_interval {
                    if should_exit.load(Ordering::Relaxed) || is_paused.load(Ordering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                let _ = event_transmitter.send(NetworkEvent::ProbeCycleComplete);
                completed_cycles = completed_cycles.saturating_add(1);
                if config.report && completed_cycles >= config.report_cycles {
                    break;
                }
            }
        })
    }

    fn create_icmp_socket() -> io::Result<(socket2::Socket, SocketKind)> {
        use socket2::{Domain, Protocol, Socket, Type};

        #[cfg(target_os = "linux")]
        {
            match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
                Ok(socket) => Ok((socket, SocketKind::Raw)),
                Err(raw_error) => Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
                    .map(|socket| (socket, SocketKind::Datagram))
                    .map_err(|datagram_error| {
                        io::Error::new(
                            datagram_error.kind(),
                            format!(
                                "非特权 ICMP socket: {datagram_error}; Raw Socket: {raw_error}"
                            ),
                        )
                    }),
            }
        }

        #[cfg(not(target_os = "linux"))]
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .map(|socket| (socket, SocketKind::Raw))
    }

    #[cfg(unix)]
    fn extract_probe_metadata(
        packet_data: &[u8],
        socket_kind: SocketKind,
    ) -> Option<IcmpMatchMetadata> {
        if matches!(socket_kind, SocketKind::Datagram) {
            if packet_data.len() < 8 {
                return None;
            }

            return match (packet_data[0], packet_data[1]) {
                (0, 0) => Some(IcmpMatchMetadata {
                    response_type: IcmpResponseType::EchoReply,
                    process_identifier: u16::from_be_bytes([packet_data[4], packet_data[5]]),
                    sequence_number: u16::from_be_bytes([packet_data[6], packet_data[7]]),
                }),
                _ => None,
            };
        }

        if packet_data.len() < 20 {
            return None;
        }

        if packet_data[0] >> 4 != 4 || packet_data[9] != 1 {
            return None;
        }

        let outer_ihl = (packet_data[0] & 0x0F) as usize;
        if outer_ihl < 5 {
            return None;
        }

        let outer_ip_header_length = outer_ihl * 4;
        if packet_data.len() < outer_ip_header_length + 8 {
            return None;
        }

        let icmp_type = packet_data[outer_ip_header_length];
        let icmp_code = packet_data[outer_ip_header_length + 1];

        match icmp_type {
            0 => {
                if icmp_code != 0 {
                    return None;
                }

                let identifier = u16::from_be_bytes([
                    packet_data[outer_ip_header_length + 4],
                    packet_data[outer_ip_header_length + 5],
                ]);
                let sequence_number = u16::from_be_bytes([
                    packet_data[outer_ip_header_length + 6],
                    packet_data[outer_ip_header_length + 7],
                ]);

                Some(IcmpMatchMetadata {
                    response_type: IcmpResponseType::EchoReply,
                    process_identifier: identifier,
                    sequence_number,
                })
            }
            11 => {
                if icmp_code != 0 {
                    return None;
                }

                let inner_ip_offset = outer_ip_header_length + 8;
                if packet_data.len() < inner_ip_offset + 20 {
                    return None;
                }

                if packet_data[inner_ip_offset] >> 4 != 4 || packet_data[inner_ip_offset + 9] != 1 {
                    return None;
                }

                let inner_ihl = (packet_data[inner_ip_offset] & 0x0F) as usize;
                if inner_ihl < 5 {
                    return None;
                }

                let inner_ip_header_length = inner_ihl * 4;
                let inner_icmp_offset = inner_ip_offset + inner_ip_header_length;

                if packet_data.len() < inner_icmp_offset + 8 {
                    return None;
                }

                let identifier = u16::from_be_bytes([
                    packet_data[inner_icmp_offset + 4],
                    packet_data[inner_icmp_offset + 5],
                ]);
                let sequence_number = u16::from_be_bytes([
                    packet_data[inner_icmp_offset + 6],
                    packet_data[inner_icmp_offset + 7],
                ]);

                Some(IcmpMatchMetadata {
                    response_type: IcmpResponseType::TimeExceeded,
                    process_identifier: identifier,
                    sequence_number,
                })
            }
            _ => None,
        }
    }

    #[cfg(unix)]
    fn build_echo_request(sequence_number: u16, process_identifier: u16) -> [u8; 8] {
        let mut packet = [0u8; 8];
        packet[0] = 8;
        packet[1] = 0;
        packet[4] = (process_identifier >> 8) as u8;
        packet[5] = (process_identifier & 0xff) as u8;
        packet[6] = (sequence_number >> 8) as u8;
        packet[7] = (sequence_number & 0xff) as u8;

        let mut sum = 0u32;
        for chunk in packet.chunks_exact(2) {
            sum = sum.wrapping_add((chunk[0] as u32) << 8 | (chunk[1] as u32));
        }

        while (sum >> 16) > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        let checksum = !(sum as u16);
        packet[2] = (checksum >> 8) as u8;
        packet[3] = (checksum & 0xff) as u8;
        packet
    }
}

// ============================================================================
// DNS 解析引擎及 TUI 渲染模块
// ============================================================================
pub struct BackgroundDnsResolver;

impl BackgroundDnsResolver {
    pub fn spawn(
        ip_query_receiver: Receiver<IpAddr>,
        resolution_transmitter: Sender<DnsResolvedEvent>,
        should_exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            while !should_exit.load(Ordering::Relaxed) {
                match ip_query_receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(ip_address) => {
                        let worker_transmitter = resolution_transmitter.clone();
                        thread::spawn(move || {
                            // libc reverse-DNS lookup has no portable cancellation API. Keep it
                            // outside the control loop so shutdown is not blocked by a slow resolver.
                            let resolved_hostname = lookup_addr(&ip_address)
                                .ok()
                                .filter(|hostname| !contains_unsafe_display_characters(hostname))
                                .unwrap_or_else(|| ip_address.to_string());

                            let _ = worker_transmitter.send(DnsResolvedEvent {
                                original_ip: ip_address,
                                resolved_hostname,
                            });
                        });
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
    }

    pub fn resolve_target_host(host: &str, prefer_ipv6: bool) -> Result<IpAddr, String> {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            if prefer_ipv6 {
                return Err(String::from("--ipv6 requires an IPv6 target"));
            }
            return Ok(IpAddr::V4(ip));
        }
        if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
            if !prefer_ipv6 {
                return Err(String::from("IPv6 target requires --ipv6"));
            }
            if ip.segments()[0] & 0xffc0 == 0xfe80 {
                return Err(String::from(
                    "link-local IPv6 targets require an interface scope and are not supported",
                ));
            }
            return Ok(IpAddr::V6(ip));
        }

        let lookup_string = format!("{}:0", host);
        match lookup_string.to_socket_addrs() {
            Ok(mut socket_addresses) => {
                for socket_address in socket_addresses.by_ref() {
                    match socket_address {
                        std::net::SocketAddr::V4(address) if !prefer_ipv6 => {
                            return Ok(IpAddr::V4(*address.ip()));
                        }
                        std::net::SocketAddr::V6(address) if prefer_ipv6 => {
                            return Ok(IpAddr::V6(*address.ip()));
                        }
                        _ => {}
                    }
                }

                Err(format!(
                    "DNS 解析成功，但未找到与主机 '{}' 匹配的 IPv4 地址",
                    host
                ))
            }
            Err(error) => Err(format!("无法解析主机 '{}': {}", host, error)),
        }
    }
}

pub struct MtrApplication {
    target_hostname: String,
    target_ip: IpAddr,
    route_hops: Vec<HopStatistic>,
    final_destination_ttl: Option<u8>,
    network_event_receiver: Receiver<NetworkEvent>,
    dns_query_transmitter: Sender<IpAddr>,
    dns_result_receiver: Receiver<DnsResolvedEvent>,
    ip_to_hostname_cache: HashMap<IpAddr, String>,
    in_flight_dns_queries: HashSet<IpAddr>,
    pub is_paused: Arc<AtomicBool>,
    network_status: NetworkStatus,
    config: ProbeConfig,
    completed_cycles: u32,
    show_dns: bool,
    started_at: chrono::DateTime<chrono::Local>,
}

impl MtrApplication {
    #[allow(clippy::too_many_arguments)]
    fn new(
        target_hostname: String,
        target_ip: IpAddr,
        network_event_receiver: Receiver<NetworkEvent>,
        dns_query_transmitter: Sender<IpAddr>,
        dns_result_receiver: Receiver<DnsResolvedEvent>,
        is_paused: Arc<AtomicBool>,
        network_status: NetworkStatus,
        config: ProbeConfig,
    ) -> Self {
        Self {
            target_hostname,
            target_ip,
            route_hops: Vec::new(),
            final_destination_ttl: None,
            network_event_receiver,
            dns_query_transmitter,
            dns_result_receiver,
            ip_to_hostname_cache: HashMap::new(),
            in_flight_dns_queries: HashSet::new(),
            is_paused,
            network_status,
            show_dns: !config.no_dns,
            config,
            completed_cycles: 0,
            started_at: chrono::Local::now(),
        }
    }

    pub fn toggle_pause(&self) {
        let current_state = self.is_paused.load(Ordering::Relaxed);
        self.is_paused.store(!current_state, Ordering::Relaxed);
    }

    pub fn toggle_dns(&mut self) {
        if self.config.no_dns {
            return;
        }
        self.show_dns = !self.show_dns;
    }

    pub fn reset_all_statistics(&mut self) {
        for hop in &mut self.route_hops {
            hop.reset_statistics();
        }
        self.final_destination_ttl = None;
    }

    fn get_or_create_hop(&mut self, ttl: u8) -> &mut HopStatistic {
        let existing_position = self.route_hops.iter().position(|hop| hop.ttl == ttl);
        if let Some(position) = existing_position {
            return &mut self.route_hops[position];
        }

        self.route_hops.push(HopStatistic::new(ttl, None));
        self.route_hops.sort_by_key(|hop| hop.ttl);

        let inserted_position = self
            .route_hops
            .iter()
            .position(|hop| hop.ttl == ttl)
            .expect("刚插入的 TTL 必须存在");

        &mut self.route_hops[inserted_position]
    }

    pub fn dispatch_incoming_events(&mut self) {
        while let Ok(event) = self.network_event_receiver.try_recv() {
            match event {
                NetworkEvent::RouteHopDiscovered { ttl, ip_address } => {
                    if self.show_dns
                        && !self.in_flight_dns_queries.contains(&ip_address)
                        && !self.ip_to_hostname_cache.contains_key(&ip_address)
                    {
                        self.in_flight_dns_queries.insert(ip_address);
                        let _ = self.dns_query_transmitter.send(ip_address);
                    }

                    let hop = self.get_or_create_hop(ttl);
                    if hop.ip_address.is_none() {
                        hop.ip_address = Some(ip_address);
                    }
                }
                NetworkEvent::EchoProbeResult {
                    ttl,
                    latency_ms,
                    reached_target,
                } => {
                    if reached_target
                        && self
                            .final_destination_ttl
                            .is_none_or(|known_final_ttl| ttl < known_final_ttl)
                    {
                        self.final_destination_ttl = Some(ttl);
                    }

                    let hop = self.get_or_create_hop(ttl);
                    hop.record_probe_result(latency_ms);
                }
                NetworkEvent::ProbeCycleComplete => {
                    self.completed_cycles = self.completed_cycles.saturating_add(1);
                }
                NetworkEvent::ProbeError {
                    message: error_message,
                    suggest_capability,
                } => {
                    self.network_status = NetworkStatus::Unavailable {
                        details: error_message,
                        capability_command: suggest_capability.then(capability_command).flatten(),
                    };
                }
            }
        }

        while let Ok(dns_event) = self.dns_result_receiver.try_recv() {
            self.in_flight_dns_queries.remove(&dns_event.original_ip);
            self.ip_to_hostname_cache
                .insert(dns_event.original_ip, dns_event.resolved_hostname);
        }

        if let Some(final_ttl) = self.final_destination_ttl {
            self.route_hops.retain(|hop| hop.ttl <= final_ttl);
        }
    }

    pub fn render_frame(&self, frame: &mut Frame) {
        let status_lines = self.network_status_message();
        let guide_lines = self.guide_message();
        let status_height = (wrapped_line_count(&status_lines, frame.size().width) as u16)
            .min(frame.size().height.saturating_sub(1));
        let guide_height = (wrapped_line_count(&guide_lines, frame.size().width) as u16)
            .min(frame.size().height.saturating_sub(1 + status_height));
        let layout_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(1),
                    Constraint::Length(status_height),
                    Constraint::Length(guide_height),
                    Constraint::Min(0),
                ]
                .as_ref(),
            )
            .split(frame.size());

        self.render_header(frame, layout_chunks[0]);
        self.render_network_status(frame, layout_chunks[1]);
        self.render_guide(frame, layout_chunks[2]);
        self.render_statistics_table(frame, layout_chunks[3]);
    }

    fn network_status_message(&self) -> String {
        network_status_message(&self.network_status)
    }

    fn render_network_status(&self, frame: &mut Frame, area: Rect) {
        let style = match &self.network_status {
            NetworkStatus::Ready => Style::default(),
            NetworkStatus::Reduced { .. } => Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            NetworkStatus::Unavailable { .. } => {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            }
        };
        let paragraph = Paragraph::new(self.network_status_message())
            .style(style)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::NONE));
        frame.render_widget(paragraph, area);
    }
    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let header_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(70), Constraint::Percentage(30)].as_ref())
            .split(area);

        let header_title = format!(
            " My Traceroute (mtr) to {} ({})",
            self.target_hostname, self.target_ip
        );

        let title_block =
            Paragraph::new(header_title).style(Style::default().add_modifier(Modifier::BOLD));

        let time_block = Paragraph::new(current_time)
            .style(Style::default().add_modifier(Modifier::BOLD))
            .alignment(Alignment::Right);

        frame.render_widget(title_block, header_chunks[0]);
        frame.render_widget(time_block, header_chunks[1]);
    }

    fn render_guide(&self, frame: &mut Frame, area: Rect) {
        let guide_text = self.guide_message();
        let mut style = Style::default().fg(Color::DarkGray);
        if self.is_paused.load(Ordering::Relaxed) {
            style = style.fg(Color::Yellow).add_modifier(Modifier::BOLD);
        }

        let paragraph = Paragraph::new(guide_text)
            .style(style)
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }

    fn guide_message(&self) -> String {
        let pause_status = if self.is_paused.load(Ordering::Relaxed) {
            " [PAUSED]"
        } else {
            ""
        };

        let dns_hint = if self.config.no_dns {
            String::new()
        } else {
            format!("   [n] DNS ({})", if self.show_dns { "on" } else { "off" })
        };
        format!(
            " Keys: [p] pause/resume{}   [r] restart{}   [q] quit\n ICMP {} | {:.1}s | max-hops {} | cycles {}",
            pause_status,
            dns_hint,
            if self.target_ip.is_ipv4() { "IPv4" } else { "IPv6" },
            self.config.interval.as_secs_f64(),
            self.config.max_hops,
            self.completed_cycles,
        )
    }

    fn render_statistics_table(&self, frame: &mut Frame, area: Rect) {
        let table_headers = [
            "Host", "Loss%", "Snt", "Last", "Avg", "Best", "Wrst", "StDev",
        ]
        .iter()
        .map(|header_title| Cell::from(*header_title).style(Style::default().fg(Color::DarkGray)));

        let header_row = Row::new(table_headers)
            .style(Style::default().add_modifier(Modifier::BOLD))
            .height(1)
            .bottom_margin(1);

        let data_rows = self.route_hops.iter().map(|hop| {
            let display_name = match hop.ip_address {
                None => String::from("???"),
                Some(ip_address) => {
                    let ip_string = ip_address.to_string();
                    if self.show_dns {
                        if let Some(hostname) = self.ip_to_hostname_cache.get(&ip_address) {
                            if hostname != &ip_string {
                                format!("{} ({})", ip_string, hostname)
                            } else {
                                ip_string
                            }
                        } else {
                            ip_string
                        }
                    } else {
                        ip_string
                    }
                }
            };

            let (loss, snt, last, avg, best, wrst, stdev) = if hop.ip_address.is_none() {
                (
                    String::from("-"),
                    String::from("-"),
                    String::from("-"),
                    String::from("-"),
                    String::from("-"),
                    String::from("-"),
                    String::from("-"),
                )
            } else {
                (
                    format!("{:.1}%", hop.packet_loss_percentage()),
                    hop.packets_sent.to_string(),
                    hop.last_latency_ms
                        .map(|value| format!("{:.1}", value))
                        .unwrap_or_else(|| String::from("-")),
                    hop.average_latency_ms()
                        .map(|value| format!("{:.1}", value))
                        .unwrap_or_else(|| String::from("-")),
                    hop.best_latency_ms
                        .map(|value| format!("{:.1}", value))
                        .unwrap_or_else(|| String::from("-")),
                    hop.worst_latency_ms
                        .map(|value| format!("{:.1}", value))
                        .unwrap_or_else(|| String::from("-")),
                    hop.standard_deviation()
                        .map(|value| format!("{:.1}", value))
                        .unwrap_or_else(|| String::from("-")),
                )
            };

            let cells = vec![
                Cell::from(format!("{}. {}", hop.ttl, display_name)),
                Cell::from(loss),
                Cell::from(snt),
                Cell::from(last),
                Cell::from(avg),
                Cell::from(best),
                Cell::from(wrst),
                Cell::from(stdev),
            ];

            Row::new(cells).height(1)
        });

        let column_constraints = [
            Constraint::Percentage(45),
            Constraint::Percentage(7),
            Constraint::Percentage(7),
            Constraint::Percentage(7),
            Constraint::Percentage(7),
            Constraint::Percentage(7),
            Constraint::Percentage(7),
            Constraint::Percentage(7),
        ];

        let statistics_table = Table::new(data_rows, column_constraints)
            .header(header_row)
            .block(Block::default().borders(Borders::NONE));

        frame.render_widget(statistics_table, area);
    }
}

fn wrapped_line_count(text: &str, width: u16) -> usize {
    if text == " " {
        return 1;
    }
    let width = usize::from(width.max(1));
    text.lines()
        .map(|line| {
            let mut rows = 1usize;
            let mut current_width = 0usize;
            let mut word = String::new();
            let flush_word = |word: &mut String, rows: &mut usize, current_width: &mut usize| {
                if word.is_empty() {
                    return;
                }
                let word_width = word.chars().map(display_width).sum::<usize>();
                if word_width > width {
                    if *current_width > 0 {
                        *rows += 1;
                    }
                    *rows += word_width.div_ceil(width).saturating_sub(1);
                    let remainder = word_width % width;
                    *current_width = if remainder == 0 { width } else { remainder };
                } else if *current_width > 0 && *current_width + word_width > width {
                    *rows += 1;
                    *current_width = word_width;
                } else {
                    *current_width += word_width;
                }
                word.clear();
            };
            for character in line.chars() {
                if character.is_whitespace() {
                    flush_word(&mut word, &mut rows, &mut current_width);
                    let character_width = display_width(character);
                    if current_width + character_width > width {
                        rows += 1;
                        current_width = 0;
                    } else {
                        current_width += character_width;
                    }
                } else {
                    word.push(character);
                }
            }
            flush_word(&mut word, &mut rows, &mut current_width);
            if line.is_empty() {
                1
            } else {
                rows
            }
        })
        .sum::<usize>()
        .max(1)
}

fn display_width(character: char) -> usize {
    if character.is_ascii() {
        1
    } else {
        2
    }
}

fn contains_unsafe_display_characters(value: &str) -> bool {
    value.chars().any(|character| {
        character.is_control()
            || matches!(
                character as u32,
                0x061C
                    | 0x200B..=0x200F
                    | 0x2028..=0x2029
                    | 0x202A..=0x202E
                    | 0x2066..=0x2069
                    | 0xFEFF
            )
    })
}

fn network_status_message(status: &NetworkStatus) -> String {
    match status {
        NetworkStatus::Ready => String::from(" "),
        NetworkStatus::Reduced { capability_command } => {
            let remediation = capability_command
                .as_ref()
                .map(|command| format!(" To enable full traceroute, run: {}", command))
                .unwrap_or_else(unavailable_remediation);
            format!(
                " WARNING: Raw ICMP unavailable; using Datagram mode. Intermediate hops may show ???.\n{}\n Ensure the executable and its parent directories are not writable by unprivileged users.",
                remediation
            )
        }
        NetworkStatus::Unavailable {
            details,
            capability_command,
        } => {
            let remediation = capability_command
                .as_ref()
                .map(|command| format!(" Run: {}", command))
                .unwrap_or_else(unavailable_remediation);
            format!(
                " ERROR: ICMP probing unavailable: {}.{}\n Ensure the executable and its parent directories are not writable by unprivileged users.",
                details,
                remediation
            )
        }
    }
}

fn unavailable_remediation() -> String {
    #[cfg(windows)]
    {
        String::from(" Check the Windows IP Helper service and firewall policy.")
    }
    #[cfg(not(windows))]
    {
        String::from(" Run with permission to create raw ICMP sockets.")
    }
}

#[cfg(unix)]
fn detect_network_status() -> NetworkStatus {
    match ActiveNetworkProber::create_icmp_socket() {
        Ok((_, SocketKind::Raw)) => NetworkStatus::Ready,
        Ok((_, SocketKind::Datagram)) => NetworkStatus::Reduced {
            #[cfg(target_os = "linux")]
            capability_command: capability_command(),
            #[cfg(not(target_os = "linux"))]
            capability_command: None,
        },
        Err(error) => NetworkStatus::Unavailable {
            details: error.to_string(),
            #[cfg(target_os = "linux")]
            capability_command: capability_command(),
            #[cfg(not(target_os = "linux"))]
            capability_command: None,
        },
    }
}

#[cfg(unix)]
fn detect_ipv6_network_status() -> NetworkStatus {
    use socket2::{Domain, Protocol, Socket, Type};
    match Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6)) {
        Ok(_) => NetworkStatus::Reduced {
            capability_command: None,
        },
        Err(datagram_error) => match Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)) {
            Ok(_) => NetworkStatus::Unavailable {
                details: String::from(
                    "ICMPv6 datagram socket unavailable; raw checksum support is required",
                ),
                capability_command: None,
            },
            Err(raw_error) => NetworkStatus::Unavailable {
                details: format!("ICMPv6 socket unavailable: {datagram_error}; raw: {raw_error}"),
                capability_command: None,
            },
        },
    }
}

#[cfg(windows)]
fn detect_ipv6_network_status() -> NetworkStatus {
    NetworkStatus::Unavailable {
        details: String::from("Windows IPv6 ICMP probing is not implemented"),
        capability_command: None,
    }
}

#[cfg(windows)]
fn detect_network_status() -> NetworkStatus {
    windows_network_status()
}

#[cfg(unix)]
fn spawn_target_probe(
    event_transmitter: SyncSender<NetworkEvent>,
    target_ip: IpAddr,
    is_paused: Arc<AtomicBool>,
    should_exit: Arc<AtomicBool>,
    config: ProbeConfig,
) -> JoinHandle<()> {
    match target_ip {
        IpAddr::V4(address) => {
            ActiveNetworkProber::spawn(event_transmitter, address, is_paused, should_exit, config)
        }
        IpAddr::V6(address) => ActiveIpv6NetworkProber::spawn(
            event_transmitter,
            address,
            is_paused,
            should_exit,
            config,
        ),
    }
}

#[cfg(windows)]
fn spawn_target_probe(
    event_transmitter: SyncSender<NetworkEvent>,
    target_ip: IpAddr,
    is_paused: Arc<AtomicBool>,
    should_exit: Arc<AtomicBool>,
    config: ProbeConfig,
) -> JoinHandle<()> {
    let address = match target_ip {
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => {
            return thread::spawn(move || {
                let _ = event_transmitter.send(NetworkEvent::ProbeError {
                    message: String::from("Windows IPv6 ICMP probing is not implemented"),
                    suggest_capability: false,
                });
            });
        }
    };
    ActiveNetworkProber::spawn(event_transmitter, address, is_paused, should_exit, config)
}

// ============================================================================
// 程序入口
// ============================================================================
fn main() -> io::Result<()> {
    let args = CliArgs::parse();
    let config = match ProbeConfig::from_args(&args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    };
    let target_host = args.target;

    let target_ip = match BackgroundDnsResolver::resolve_target_host(&target_host, args.ipv6) {
        Ok(ip) => ip,
        Err(error_message) => {
            eprintln!("错误: {}", error_message);
            std::process::exit(1);
        }
    };

    #[cfg(windows)]
    if matches!(target_ip, IpAddr::V6(_)) {
        eprintln!("error: Windows IPv6 ICMP probing is not implemented yet");
        std::process::exit(2);
    }

    if config.report {
        return run_report_mode(target_host, target_ip, config);
    }

    let network_status = match target_ip {
        IpAddr::V4(_) => detect_network_status(),
        IpAddr::V6(_) => detect_ipv6_network_status(),
    };

    let mut terminal_session = TerminalSession::enter()?;

    let event_capacity = NETWORK_EVENT_CAPACITY.max(config.max_hops as usize * 2 + 16);
    let (network_tx, network_rx) = mpsc::sync_channel(event_capacity);
    let (dns_query_tx, dns_query_rx) = mpsc::channel();
    let (dns_result_tx, dns_result_rx) = mpsc::channel();

    let is_paused = Arc::new(AtomicBool::new(false));
    let should_exit = Arc::new(AtomicBool::new(false));

    let network_thread = if matches!(&network_status, NetworkStatus::Unavailable { .. }) {
        None
    } else {
        Some(spawn_target_probe(
            network_tx,
            target_ip,
            Arc::clone(&is_paused),
            Arc::clone(&should_exit),
            config.clone(),
        ))
    };

    let dns_thread = if config.no_dns {
        None
    } else {
        Some(BackgroundDnsResolver::spawn(
            dns_query_rx,
            dns_result_tx,
            Arc::clone(&should_exit),
        ))
    };

    let mut application = MtrApplication::new(
        target_host,
        target_ip,
        network_rx,
        dns_query_tx.clone(),
        dns_result_rx,
        is_paused,
        network_status,
        config.clone(),
    );

    let refresh_interval = Duration::from_millis(100);
    let mut last_tick_timestamp = Instant::now();

    loop {
        terminal_session
            .terminal_mut()
            .draw(|frame| application.render_frame(frame))?;

        let timeout_duration = refresh_interval
            .checked_sub(last_tick_timestamp.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout_duration)? {
            if let Event::Key(key_event) = event::read()? {
                if key_event.kind == KeyEventKind::Press {
                    match key_event.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('c')
                            if key_event.modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            break
                        }
                        KeyCode::Char('p') => application.toggle_pause(),
                        KeyCode::Char('r') => application.reset_all_statistics(),
                        KeyCode::Char('n') => application.toggle_dns(),
                        _ => {}
                    }
                }
            }
        }

        if last_tick_timestamp.elapsed() >= refresh_interval {
            application.dispatch_incoming_events();
            last_tick_timestamp = Instant::now();
        }
    }

    should_exit.store(true, Ordering::Relaxed);

    drop(application);
    drop(dns_query_tx);
    drop(terminal_session);
    if let Some(network_thread) = network_thread {
        network_thread
            .join()
            .map_err(|_| io::Error::other("network probe thread panicked"))?;
    }
    if let Some(dns_thread) = dns_thread {
        let _ = dns_thread.join();
    }

    Ok(())
}

fn run_report_mode(target_host: String, target_ip: IpAddr, config: ProbeConfig) -> io::Result<()> {
    let network_status = match target_ip {
        IpAddr::V4(_) => detect_network_status(),
        IpAddr::V6(_) => detect_ipv6_network_status(),
    };

    if let NetworkStatus::Unavailable { .. } = &network_status {
        eprintln!("{}", network_status_message(&network_status));
        return Err(io::Error::other(
            "ICMP probing is unavailable; cannot run report mode",
        ));
    }
    if matches!(&network_status, NetworkStatus::Reduced { .. }) {
        eprintln!("{}", network_status_message(&network_status));
    }

    let event_capacity = NETWORK_EVENT_CAPACITY.max(config.max_hops as usize * 2 + 16);
    let (network_tx, network_rx) = mpsc::sync_channel(event_capacity);
    let (dns_query_tx, dns_query_rx) = mpsc::channel();
    let (dns_result_tx, dns_result_rx) = mpsc::channel();
    let is_paused = Arc::new(AtomicBool::new(false));
    let should_exit = Arc::new(AtomicBool::new(false));
    let network_thread = spawn_target_probe(
        network_tx,
        target_ip,
        Arc::clone(&is_paused),
        Arc::clone(&should_exit),
        config.clone(),
    );
    let dns_thread = if config.no_dns {
        None
    } else {
        Some(BackgroundDnsResolver::spawn(
            dns_query_rx,
            dns_result_tx,
            Arc::clone(&should_exit),
        ))
    };
    let mut application = MtrApplication::new(
        target_host,
        target_ip,
        network_rx,
        dns_query_tx.clone(),
        dns_result_rx,
        is_paused,
        network_status,
        config.clone(),
    );

    while application.completed_cycles < config.report_cycles {
        thread::sleep(Duration::from_millis(50));
        application.dispatch_incoming_events();
        if application.completed_cycles < config.report_cycles && network_thread.is_finished() {
            thread::sleep(Duration::from_millis(20));
            application.dispatch_incoming_events();
            if application.completed_cycles < config.report_cycles {
                should_exit.store(true, Ordering::Relaxed);
                if !matches!(&application.network_status, NetworkStatus::Ready) {
                    eprintln!("{}", network_status_message(&application.network_status));
                }
                drop(application);
                drop(dns_query_tx);
                let join_result = network_thread.join();
                if let Some(dns_thread) = dns_thread {
                    let _ = dns_thread.join();
                }
                return Err(match join_result {
                    Ok(()) => io::Error::other(
                        "probe thread exited before completing the requested cycles",
                    ),
                    Err(_) => io::Error::other(
                        "probe thread panicked before completing the requested cycles",
                    ),
                });
            }
        }
    }

    while !network_thread.is_finished() {
        application.dispatch_incoming_events();
        thread::sleep(Duration::from_millis(20));
    }
    network_thread
        .join()
        .map_err(|_| io::Error::other("network probe thread panicked"))?;
    application.dispatch_incoming_events();
    let dns_deadline = Instant::now() + Duration::from_secs(2);
    while !application.in_flight_dns_queries.is_empty() && Instant::now() < dns_deadline {
        thread::sleep(Duration::from_millis(20));
        application.dispatch_incoming_events();
    }
    if application
        .route_hops
        .iter()
        .all(|hop| hop.ip_address.is_none())
    {
        should_exit.store(true, Ordering::Relaxed);
        eprintln!(
            "no probe results were recorded; check network connectivity and ICMP permissions"
        );
        drop(application);
        drop(dns_query_tx);
        if let Some(dns_thread) = dns_thread {
            let _ = dns_thread.join();
        }
        return Err(io::Error::other("no probe results were recorded"));
    }
    let report_result = print_report(&application);
    should_exit.store(true, Ordering::Relaxed);
    drop(application);
    drop(dns_query_tx);
    if let Some(dns_thread) = dns_thread {
        let _ = dns_thread.join();
    }
    match report_result {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}

fn print_report(application: &MtrApplication) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(
        output,
        "Start: {} ({} -> {})",
        application.started_at.format("%Y-%m-%dT%H:%M:%S"),
        application.target_hostname,
        application.target_ip
    )?;
    writeln!(
        output,
        "    {:<32} {:>6} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5}",
        "HOST", "Loss%", "Snt", "Last", "Avg", "Best", "Wrst", "StDev"
    )?;
    for hop in &application.route_hops {
        let host = hop
            .ip_address
            .map(|address| {
                let ip_string = address.to_string();
                if application.show_dns {
                    application
                        .ip_to_hostname_cache
                        .get(&address)
                        .filter(|hostname| hostname.as_str() != ip_string.as_str())
                        .map(|hostname| format!("{} ({})", ip_string, hostname))
                        .unwrap_or(ip_string)
                } else {
                    ip_string
                }
            })
            .unwrap_or_else(|| "???".to_string());
        let format_latency = |value: Option<f64>| {
            value
                .map(|number| format!("{:>5.1}", number))
                .unwrap_or_else(|| "    -".to_string())
        };
        let average = format_latency(hop.average_latency_ms());
        let best = format_latency(hop.best_latency_ms);
        let worst = format_latency(hop.worst_latency_ms);
        let stdev = format_latency(hop.standard_deviation());
        writeln!(
            output,
            "{:>2}. {:<32} {:>5.1}% {:>5} {} {} {} {} {}",
            hop.ttl,
            host,
            hop.packet_loss_percentage(),
            hop.packets_sent,
            format_latency(hop.last_latency_ms),
            average,
            best,
            worst,
            stdev
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn builds_echo_request_with_valid_checksum() {
        let packet = ActiveNetworkProber::build_echo_request(7, 42);
        let checksum: u32 = packet
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]) as u32)
            .fold(0u32, |sum, value| sum.wrapping_add(value));
        assert_eq!((checksum & 0xffff) + (checksum >> 16), 0xffff);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(
            shell_quote("/tmp/mtr user's binary"),
            "'/tmp/mtr user'\\''s binary'"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capability_command_contains_required_capability() {
        let command = capability_command();
        assert!(
            command.is_some_and(|command| { command.starts_with("sudo setcap cap_net_raw+ep ") })
        );
    }

    #[test]
    fn network_status_messages_explain_each_state() {
        assert_eq!(network_status_message(&NetworkStatus::Ready), " ");

        let reduced = network_status_message(&NetworkStatus::Reduced {
            capability_command: Some(String::from("sudo setcap cap_net_raw+ep 'mtr'")),
        });
        assert!(reduced.contains("Datagram"));
        assert!(reduced.contains("cap_net_raw"));

        let unavailable = network_status_message(&NetworkStatus::Unavailable {
            details: String::from("permission denied"),
            capability_command: Some(String::from("sudo setcap cap_net_raw+ep 'mtr'")),
        });
        assert!(unavailable.contains("permission denied"));
        assert!(unavailable.contains("setcap"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_invalid_ip_protocol_and_truncated_packets() {
        assert!(ActiveNetworkProber::extract_probe_metadata(&[0; 20], SocketKind::Raw).is_none());
        assert!(
            ActiveNetworkProber::extract_probe_metadata(&[0x45; 12], SocketKind::Raw).is_none()
        );
        assert!(
            ActiveNetworkProber::extract_probe_metadata(&[0; 7], SocketKind::Datagram).is_none()
        );

        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 17;
        assert!(ActiveNetworkProber::extract_probe_metadata(&packet, SocketKind::Raw).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn parses_echo_reply_metadata() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 1;
        packet[20] = 0;
        packet[21] = 0;
        packet[24..26].copy_from_slice(&42u16.to_be_bytes());
        packet[26..28].copy_from_slice(&7u16.to_be_bytes());

        let metadata = ActiveNetworkProber::extract_probe_metadata(&packet, SocketKind::Raw)
            .expect("valid reply");
        assert_eq!(metadata.process_identifier, 42);
        assert_eq!(metadata.sequence_number, 7);
        assert!(matches!(
            metadata.response_type,
            IcmpResponseType::EchoReply
        ));
    }

    #[cfg(unix)]
    #[test]
    fn parses_datagram_echo_reply_without_ip_header() {
        let mut packet = vec![0u8; 8];
        packet[0] = 0;
        packet[4..6].copy_from_slice(&42u16.to_be_bytes());
        packet[6..8].copy_from_slice(&7u16.to_be_bytes());

        let metadata = ActiveNetworkProber::extract_probe_metadata(&packet, SocketKind::Datagram)
            .expect("valid datagram reply");
        assert_eq!(metadata.sequence_number, 7);
        assert!(matches!(
            metadata.response_type,
            IcmpResponseType::EchoReply
        ));
    }

    #[cfg(unix)]
    #[test]
    fn parses_ipv6_echo_reply_and_time_exceeded_metadata() {
        let mut echo_reply = vec![0u8; 48];
        echo_reply[0] = 0x60;
        echo_reply[6] = 58;
        echo_reply[40] = 129;
        echo_reply[44..46].copy_from_slice(&42u16.to_be_bytes());
        echo_reply[46..48].copy_from_slice(&7u16.to_be_bytes());
        let echo_metadata = extract_ipv6_probe_metadata(&echo_reply).expect("IPv6 echo reply");
        assert!(matches!(
            echo_metadata.response_type,
            IcmpResponseType::EchoReply
        ));
        assert_eq!(echo_metadata.process_identifier, 42);
        assert_eq!(echo_metadata.sequence_number, 7);

        let mut time_exceeded = vec![0u8; 96];
        time_exceeded[0] = 0x60;
        time_exceeded[6] = 58;
        time_exceeded[40] = 3;
        time_exceeded[48] = 0x60;
        time_exceeded[54] = 58;
        time_exceeded[88] = 128;
        time_exceeded[92..94].copy_from_slice(&42u16.to_be_bytes());
        time_exceeded[94..96].copy_from_slice(&7u16.to_be_bytes());
        let transit_metadata =
            extract_ipv6_probe_metadata(&time_exceeded).expect("IPv6 time exceeded");
        assert!(matches!(
            transit_metadata.response_type,
            IcmpResponseType::TimeExceeded
        ));
        assert_eq!(transit_metadata.process_identifier, 42);
        assert_eq!(transit_metadata.sequence_number, 7);

        assert!(extract_ipv6_probe_metadata(&echo_reply[..47]).is_none());
        echo_reply[41] = 1;
        assert!(extract_ipv6_probe_metadata(&echo_reply).is_none());

        let mut headerless = vec![0u8; 56];
        headerless[0] = 3;
        headerless[1] = 0;
        headerless[8] = 0x60;
        headerless[14] = 58;
        headerless[48] = 128;
        headerless[52..54].copy_from_slice(&42u16.to_be_bytes());
        headerless[54..56].copy_from_slice(&7u16.to_be_bytes());
        assert!(matches!(
            extract_ipv6_probe_metadata(&headerless)
                .expect("headerless IPv6 time exceeded")
                .response_type,
            IcmpResponseType::TimeExceeded
        ));
    }

    #[cfg(unix)]
    #[test]
    fn builds_ipv6_echo_request() {
        let packet = build_ipv6_echo_request(7, 42);
        assert_eq!(packet[0], 128);
        assert_eq!(&packet[4..6], &42u16.to_be_bytes());
        assert_eq!(&packet[6..8], &7u16.to_be_bytes());
    }

    #[test]
    fn calculates_statistics() {
        let mut statistic = HopStatistic::new(1, None);
        statistic.record_probe_result(Some(10.0));
        statistic.record_probe_result(Some(20.0));
        statistic.record_probe_result(None);

        assert_eq!(statistic.packets_sent, 3);
        assert_eq!(statistic.packets_received, 2);
        assert!((statistic.packet_loss_percentage() - 33.3333).abs() < 0.01);
        assert_eq!(statistic.average_latency_ms(), Some(15.0));
        assert!((statistic.standard_deviation().unwrap() - 7.071).abs() < 0.01);
    }

    #[test]
    fn validates_probe_configuration() {
        let args = CliArgs::parse_from([
            "mtr",
            "127.0.0.1",
            "--report",
            "--report-cycles",
            "3",
            "--interval",
            "0.8",
            "--max-hops",
            "12",
        ]);
        let config = ProbeConfig::from_args(&args).expect("valid config");
        assert!(config.report);
        assert_eq!(config.report_cycles, 3);
        assert_eq!(config.max_hops, 12);
        assert_eq!(config.interval, Duration::from_millis(800));
    }

    #[test]
    fn rejects_invalid_interval() {
        assert!(CliArgs::try_parse_from(["mtr", "127.0.0.1", "--report-cycles", "3"]).is_err());

        let args = CliArgs::parse_from(["mtr", "127.0.0.1", "--interval", "0.01"]);
        assert!(ProbeConfig::from_args(&args).is_err());
    }

    #[test]
    fn resolves_explicit_ipv6_target_by_address_family() {
        assert_eq!(
            BackgroundDnsResolver::resolve_target_host("::1", true).unwrap(),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        );
        assert!(BackgroundDnsResolver::resolve_target_host("::1", false).is_err());
    }
}
