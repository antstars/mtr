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
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame, Terminal,
};
use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

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
}

#[derive(Debug, Clone)]
pub struct HopStatistic {
    pub ttl: u8,
    pub ip_address: Option<Ipv4Addr>,
    pub packets_sent: u32,
    pub packets_received: u32,
    pub last_latency_ms: Option<f64>,
    pub best_latency_ms: Option<f64>,
    pub worst_latency_ms: Option<f64>,
    pub mean_latency_ms: f64,
    pub m2_latency_ms: f64,
}

impl HopStatistic {
    pub fn new(ttl: u8, ip_address: Option<Ipv4Addr>) -> Self {
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
        ip_address: Ipv4Addr,
    },
    EchoProbeResult {
        ttl: u8,
        latency_ms: Option<f64>,
        reached_target: bool,
    },
}

pub struct DnsResolvedEvent {
    pub original_ip: Ipv4Addr,
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
        event_transmitter: Sender<NetworkEvent>,
        target_ipv4: Ipv4Addr,
        is_paused: Arc<AtomicBool>,
        should_exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            let maximum_route_hops: u8 = 30;
            let probe_timeout_ms: u32 = 800;
            let dynamic_max_ttl = Arc::new(AtomicU8::new(maximum_route_hops));

            let mut ttl_senders: Vec<Sender<WindowsProbeTask>> = Vec::with_capacity(maximum_route_hops as usize);
            let mut worker_join_handles: Vec<JoinHandle<()>> = Vec::with_capacity(maximum_route_hops as usize);

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
                while sleep_start_time.elapsed() < Duration::from_millis(1000) {
                    if should_exit.load(Ordering::Relaxed) || is_paused.load(Ordering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
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
        event_transmitter: Sender<NetworkEvent>,
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
                            ip_address: router_ipv4,
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

// ============================================================================
// 底层网络引擎 - Unix (Linux/macOS) 实现
// ============================================================================
#[cfg(unix)]
enum IcmpResponseType {
    EchoReply,
    TimeExceeded,
}

#[cfg(unix)]
struct IcmpMatchMetadata {
    pub response_type: IcmpResponseType,
    pub process_identifier: u16,
    pub sequence_number: u16,
}

#[cfg(unix)]
pub struct ActiveNetworkProber;

#[cfg(unix)]
impl ActiveNetworkProber {
    pub fn spawn(
        event_transmitter: Sender<NetworkEvent>,
        target_ipv4: Ipv4Addr,
        is_paused: Arc<AtomicBool>,
        should_exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::net::SocketAddr;

        thread::spawn(move || {
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
                Ok(socket_instance) => socket_instance,
                Err(error) => {
                    eprintln!("❌ 致命错误: 无法创建 Raw Socket。");
                    eprintln!("系统报错: {}", error);
                    eprintln!("💡 Linux 解决方案: 运行 `sudo setcap cap_net_raw+ep ./mtr`");
                    eprintln!("💡 macOS 解决方案: 请使用 `sudo ./mtr` 运行");
                    return;
                }
            };

            if let Err(error) = socket.set_read_timeout(Some(Duration::from_millis(10))) {
                eprintln!("❌ 致命错误: 无法设置 Raw Socket 读超时。");
                eprintln!("系统报错: {}", error);
                return;
            }

            let target_addr = SocketAddr::from((target_ipv4, 0));
            let process_identifier = std::process::id() as u16;
            let maximum_route_hops = 30;
            let dynamic_max_ttl = Arc::new(AtomicU8::new(maximum_route_hops));
            let mut sequence_number: u16 = 0;

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
                let gather_window = Duration::from_millis(800);

                while start_time.elapsed() < gather_window && !should_exit.load(Ordering::Relaxed) {
                    if let Ok((bytes_read, addr)) = socket.recv_from(&mut buffer) {
                        let source_ip = match addr.as_socket_ipv4() {
                            Some(v4_socket_addr) => *v4_socket_addr.ip(),
                            None => continue,
                        };

                        let packet_data: &[u8] = unsafe {
                            std::slice::from_raw_parts(buffer.as_ptr() as *const u8, bytes_read)
                        };

                        if let Some(metadata) = Self::extract_probe_metadata(packet_data) {
                            if metadata.process_identifier != process_identifier {
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
                                    ip_address: source_ip,
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
                if elapsed < Duration::from_millis(1000) {
                    thread::sleep(Duration::from_millis(1000) - elapsed);
                }
            }
        })
    }

    #[cfg(unix)]
    fn extract_probe_metadata(packet_data: &[u8]) -> Option<IcmpMatchMetadata> {
        if packet_data.len() < 20 {
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

                let inner_ihl = (packet_data[inner_ip_offset] & 0x0F) as usize;
                if inner_ihl < 5 {
                    return None;
                }

                let inner_ip_header_length = inner_ihl * 4;
                let inner_icmp_offset = inner_ip_offset + inner_ip_header_length;

                if packet_data.len() < inner_icmp_offset + 8 {
                    return None;
                }

                if packet_data[inner_ip_offset + 9] != 1 {
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
        ip_query_receiver: Receiver<Ipv4Addr>,
        resolution_transmitter: Sender<DnsResolvedEvent>,
        should_exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            while !should_exit.load(Ordering::Relaxed) {
                match ip_query_receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(ip_address) => {
                        let resolved_hostname =
                            lookup_addr(&IpAddr::V4(ip_address)).unwrap_or_else(|_| ip_address.to_string());

                        let _ = resolution_transmitter.send(DnsResolvedEvent {
                            original_ip: ip_address,
                            resolved_hostname,
                        });
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
    }

    pub fn resolve_target_host(host: &str) -> Result<Ipv4Addr, String> {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(ip);
        }

        let lookup_string = format!("{}:0", host);
        match lookup_string.to_socket_addrs() {
            Ok(mut socket_addresses) => {
                for socket_address in socket_addresses.by_ref() {
                    if let std::net::SocketAddr::V4(ipv4_socket_address) = socket_address {
                        return Ok(*ipv4_socket_address.ip());
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
    target_ip: Ipv4Addr,
    route_hops: Vec<HopStatistic>,
    final_destination_ttl: Option<u8>,
    network_event_receiver: Receiver<NetworkEvent>,
    dns_query_transmitter: Sender<Ipv4Addr>,
    dns_result_receiver: Receiver<DnsResolvedEvent>,
    ip_to_hostname_cache: HashMap<Ipv4Addr, String>,
    in_flight_dns_queries: HashSet<Ipv4Addr>,
    pub is_paused: Arc<AtomicBool>,
}

impl MtrApplication {
    pub fn new(
        target_hostname: String,
        target_ip: Ipv4Addr,
        network_event_receiver: Receiver<NetworkEvent>,
        dns_query_transmitter: Sender<Ipv4Addr>,
        dns_result_receiver: Receiver<DnsResolvedEvent>,
        is_paused: Arc<AtomicBool>,
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
        }
    }

    pub fn toggle_pause(&self) {
        let current_state = self.is_paused.load(Ordering::Relaxed);
        self.is_paused.store(!current_state, Ordering::Relaxed);
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
                    if !self.in_flight_dns_queries.contains(&ip_address)
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
                            .map_or(true, |known_final_ttl| ttl < known_final_ttl)
                    {
                        self.final_destination_ttl = Some(ttl);
                    }

                    let hop = self.get_or_create_hop(ttl);
                    hop.record_probe_result(latency_ms);
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
        let layout_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(1),
                    Constraint::Length(2),
                    Constraint::Min(10),
                ]
                .as_ref(),
            )
            .split(frame.size());

        self.render_header(frame, layout_chunks[0]);
        self.render_guide(frame, layout_chunks[1]);
        self.render_statistics_table(frame, layout_chunks[2]);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let current_time = chrono::Local::now()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

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
        let pause_status = if self.is_paused.load(Ordering::Relaxed) {
            " [PAUSED]"
        } else {
            ""
        };

        let guide_text = format!(
            " Keys: [p] pause/resume{}   [r] restart statistics   [q] quit",
            pause_status
        );

        let mut style = Style::default().fg(Color::DarkGray);
        if self.is_paused.load(Ordering::Relaxed) {
            style = style.fg(Color::Yellow).add_modifier(Modifier::BOLD);
        }

        let paragraph = Paragraph::new(guide_text).style(style);
        frame.render_widget(paragraph, area);
    }

    fn render_statistics_table(&self, frame: &mut Frame, area: Rect) {
        let table_headers = ["Host", "Loss%", "Snt", "Last", "Avg", "Best", "Wrst", "StDev"]
            .iter()
            .map(|header_title| {
                Cell::from(*header_title).style(Style::default().fg(Color::DarkGray))
            });

        let header_row = Row::new(table_headers)
            .style(Style::default().add_modifier(Modifier::BOLD))
            .height(1)
            .bottom_margin(1);

        let data_rows = self.route_hops.iter().map(|hop| {
            let display_name = match hop.ip_address {
                None => String::from("???"),
                Some(ip_address) => {
                    let ip_string = ip_address.to_string();
                    if let Some(hostname) = self.ip_to_hostname_cache.get(&ip_address) {
                        if hostname != &ip_string {
                            format!("{} ({})", ip_string, hostname)
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

// ============================================================================
// 程序入口
// ============================================================================
fn main() -> io::Result<()> {
    let args = CliArgs::parse();
    let target_host = args.target;

    let target_ipv4 = match BackgroundDnsResolver::resolve_target_host(&target_host) {
        Ok(ip) => ip,
        Err(error_message) => {
            eprintln!("错误: {}", error_message);
            std::process::exit(1);
        }
    };

    let mut terminal_session = TerminalSession::enter()?;

    let (network_tx, network_rx) = mpsc::channel();
    let (dns_query_tx, dns_query_rx) = mpsc::channel();
    let (dns_result_tx, dns_result_rx) = mpsc::channel();

    let is_paused = Arc::new(AtomicBool::new(false));
    let should_exit = Arc::new(AtomicBool::new(false));

    let network_join_handle = ActiveNetworkProber::spawn(
        network_tx,
        target_ipv4,
        Arc::clone(&is_paused),
        Arc::clone(&should_exit),
    );

    let dns_join_handle = BackgroundDnsResolver::spawn(
        dns_query_rx,
        dns_result_tx,
        Arc::clone(&should_exit),
    );

    let mut application = MtrApplication::new(
        target_host,
        target_ipv4,
        network_rx,
        dns_query_tx.clone(),
        dns_result_rx,
        is_paused,
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

    let _ = network_join_handle.join();
    let _ = dns_join_handle.join();

    Ok(())
}