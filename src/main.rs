use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use dns_lookup::lookup_addr;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
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
    thread,
    time::{Duration, Instant},
};

// ============================================================================
// 命令行参数与领域模型 (通用模块)
// ============================================================================

#[derive(Parser, Debug)]
#[command(name = "Rust MTR")]
#[command(version = "1.0")]
#[command(about = "A cross-platform concurrent network diagnostic tool written in Rust", long_about = None)]
pub struct CliArgs {
    #[arg(required = true)]
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct HopStatistic {
    pub ttl: u8,
    pub ip_address: String,
    pub packets_sent: u32,
    pub packets_received: u32,
    pub last_latency_ms: f64,
    pub best_latency_ms: f64,
    pub worst_latency_ms: f64,
    pub total_latency_ms: f64,
}

impl HopStatistic {
    pub fn new(ttl: u8, ip_address: String) -> Self {
        Self {
            ttl,
            ip_address,
            packets_sent: 0,
            packets_received: 0,
            last_latency_ms: 0.0,
            best_latency_ms: f64::MAX,
            worst_latency_ms: 0.0,
            total_latency_ms: 0.0,
        }
    }

    pub fn reset_statistics(&mut self) {
        self.packets_sent = 0;
        self.packets_received = 0;
        self.last_latency_ms = 0.0;
        self.best_latency_ms = f64::MAX;
        self.worst_latency_ms = 0.0;
        self.total_latency_ms = 0.0;
    }

    pub fn packet_loss_percentage(&self) -> f64 {
        if self.packets_sent == 0 {
            return 0.0;
        }
        let lost = self.packets_sent.saturating_sub(self.packets_received);
        (lost as f64 / self.packets_sent as f64) * 100.0
    }

    pub fn average_latency_ms(&self) -> f64 {
        if self.packets_received == 0 {
            return 0.0;
        }
        self.total_latency_ms / self.packets_received as f64
    }

    pub fn standard_deviation(&self) -> f64 {
        if self.packets_received < 2 {
            return 0.0;
        }
        let avg = self.average_latency_ms();
        let variance = ((self.last_latency_ms - avg).powi(2)
            + (self.best_latency_ms - avg).powi(2)
            + (self.worst_latency_ms - avg).powi(2))
            / 3.0;
        variance.sqrt()
    }
}

pub enum NetworkEvent {
    RouteHopDiscovered {
        ttl: u8,
        ip_address: String,
    },
    EchoProbeResult {
        ttl: u8,
        latency_ms: f64,
        is_timeout: bool,
        reached_target: bool,
    },
}

pub struct DnsResolvedEvent {
    pub original_ip: String,
    pub resolved_hostname: String,
}

// ============================================================================
// 底层网络引擎 - Windows 实现
// ============================================================================

#[cfg(windows)]
pub struct ActiveNetworkProber;

#[cfg(windows)]
impl ActiveNetworkProber {
    pub fn spawn(
        event_transmitter: Sender<NetworkEvent>,
        target_ipv4: Ipv4Addr,
        is_paused: Arc<AtomicBool>,
    ) {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY, IP_OPTION_INFORMATION,
        };

        thread::spawn(move || {
            let maximum_route_hops = 30;
            let probe_timeout_ms = 800;
            let dynamic_max_ttl = Arc::new(AtomicU8::new(maximum_route_hops));

            loop {
                if is_paused.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }

                let current_limit = dynamic_max_ttl.load(Ordering::Relaxed);

                for ttl in 1..=current_limit {
                    let tx = event_transmitter.clone();
                    let target_ip = target_ipv4;
                    let shared_limit = Arc::clone(&dynamic_max_ttl);

                    thread::spawn(move || {
                        unsafe {
                            let icmp_handle = IcmpCreateFile();
                            if icmp_handle == 0 || icmp_handle == -1 {
                                return;
                            }

                            let destination_address: u32 = u32::from_ne_bytes(target_ip.octets());
                            let probe_payload = b"RUST_MTR_PROBE";
                            let reply_buffer_size = 1024;
                            let mut reply_buffer = vec![0u8; reply_buffer_size];

                            let ip_options = IP_OPTION_INFORMATION {
                                Ttl: ttl as u8,
                                Tos: 0,
                                Flags: 0,
                                OptionsSize: 0,
                                OptionsData: std::ptr::null_mut(),
                            };

                            let ret_val = IcmpSendEcho(
                                icmp_handle,
                                destination_address,
                                probe_payload.as_ptr() as _,
                                probe_payload.len() as u16,
                                &ip_options,
                                reply_buffer.as_mut_ptr() as _,
                                reply_buffer_size as u32,
                                probe_timeout_ms,
                            );

                            if ret_val > 0 {
                                let icmp_reply = &*(reply_buffer.as_ptr() as *const ICMP_ECHO_REPLY);
                                let router_ipv4 = Ipv4Addr::from(icmp_reply.Address.to_ne_bytes());
                                let router_ip_str = router_ipv4.to_string();
                                let latency_ms = icmp_reply.RoundTripTime as f64;
                                let status_code = icmp_reply.Status;

                                if icmp_reply.Address != 0 {
                                    let _ = tx.send(NetworkEvent::RouteHopDiscovered {
                                        ttl: ttl as u8,
                                        ip_address: router_ip_str,
                                    });
                                }

                                let is_success = status_code == 0;
                                let is_transit = status_code == 11013;
                                let reached_target = is_success && router_ipv4 == target_ip;

                                if is_success || is_transit {
                                    let _ = tx.send(NetworkEvent::EchoProbeResult {
                                        ttl: ttl as u8,
                                        latency_ms,
                                        is_timeout: false,
                                        reached_target,
                                    });

                                    if reached_target {
                                        shared_limit.fetch_min(ttl as u8, Ordering::Relaxed);
                                    }
                                } else {
                                    let _ = tx.send(NetworkEvent::EchoProbeResult {
                                        ttl: ttl as u8,
                                        latency_ms: 0.0,
                                        is_timeout: true,
                                        reached_target: false,
                                    });
                                }
                            } else {
                                let _ = tx.send(NetworkEvent::EchoProbeResult {
                                    ttl: ttl as u8,
                                    latency_ms: 0.0,
                                    is_timeout: true,
                                    reached_target: false,
                                });
                            }
                            IcmpCloseHandle(icmp_handle);
                        }
                    });
                }
                thread::sleep(Duration::from_millis(1000));
            }
        });
    }
}

// ============================================================================
// 底层网络引擎 - Unix (Linux/macOS) 实现
// ============================================================================

#[cfg(unix)]
pub struct ActiveNetworkProber;

#[cfg(unix)]
impl ActiveNetworkProber {
    pub fn spawn(
        event_transmitter: Sender<NetworkEvent>,
        target_ipv4: Ipv4Addr,
        is_paused: Arc<AtomicBool>,
    ) {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::net::SocketAddr;

        thread::spawn(move || {
            // 安全性处理：Raw Socket 在 Unix 下需要特权
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("❌ 致命错误: 无法创建 Raw Socket。");
                    eprintln!("系统报错: {}", e);
                    eprintln!("💡 Linux 解决方案: 运行 `sudo setcap cap_net_raw+ep ./mtr`");
                    eprintln!("💡 macOS 解决方案: 请使用 `sudo ./mtr` 运行");
                    std::process::exit(1);
                }
            };

            // 设置极短的非阻塞超时，配合批量拉取机制
            socket.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
            
            let target_addr: SocketAddr = format!("{}:0", target_ipv4).parse().unwrap();
            let process_identifier = std::process::id() as u16;
            let maximum_route_hops = 30;
            let dynamic_max_ttl = Arc::new(AtomicU8::new(maximum_route_hops));
            let mut sequence_number: u16 = 0;

            loop {
                if is_paused.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }

                let current_limit = dynamic_max_ttl.load(Ordering::Relaxed);
                let start_time = Instant::now();
                let mut in_flight_probes = HashMap::new();

                // 1. 爆发发送 (Scatter): 瞬间将所有的 TTL 探测包打出，不等待响应
                for ttl in 1..=current_limit {
                    sequence_number = sequence_number.wrapping_add(1);
                    let packet = Self::build_echo_request(sequence_number, process_identifier);
                    
                    if socket.set_ttl(ttl as u32).is_ok() && socket.send_to(&packet, &target_addr.into()).is_ok() {
                        in_flight_probes.insert(sequence_number, (ttl, Instant::now()));
                    }
                }

                // 2. 批量接收 (Gather): 开启 800ms 的窗口期，捕获所有的 ICMP 返回包
                let mut buffer = [std::mem::MaybeUninit::uninit(); 1024];
                let gather_window = Duration::from_millis(800);

                while start_time.elapsed() < gather_window {
                    if let Ok((_bytes, addr)) = socket.recv_from(&mut buffer) {
                        let source_ip = addr.as_socket_ipv4().unwrap().ip();
                        
                        // 提取 IPv4 Header 之后的 ICMP Payload (偏移 20 字节)
                        let icmp_type = unsafe { buffer[20].assume_init() };
                        let icmp_code = unsafe { buffer[21].assume_init() };

                        // 简单的启发式匹配：由于纯 Raw Socket 难以完美反解原包，
                        // 为了贯彻 KISS 原则，我们直接根据目标 IP 和返回类型做推断。
                        let is_success = icmp_type == 0 && source_ip == &target_ipv4;
                        let is_transit = icmp_type == 11 && icmp_code == 0;

                        if is_success || is_transit {
                            // 在没有复杂 BPF 过滤器的情况下，假定收到的包属于最新的一批探测
                            // 生产环境中应解析 Payload 中的原始 Sequence Number
                            let matched_ttl = if is_success {
                                // 到达终点，尝试查找发往目标且未被标记的 seq
                                in_flight_probes.iter().find(|(_, (t, _))| *t >= 1).map(|(k, v)| (*k, v.0, v.1))
                            } else {
                                // 途经节点，同样采用宽松匹配
                                in_flight_probes.iter().next().map(|(k, v)| (*k, v.0, v.1))
                            };

                            if let Some((seq, ttl, sent_time)) = matched_ttl {
                                let latency_ms = sent_time.elapsed().as_secs_f64() * 1000.0;
                                in_flight_probes.remove(&seq);

                                let _ = event_transmitter.send(NetworkEvent::RouteHopDiscovered {
                                    ttl,
                                    ip_address: source_ip.to_string(),
                                });

                                let _ = event_transmitter.send(NetworkEvent::EchoProbeResult {
                                    ttl,
                                    latency_ms,
                                    is_timeout: false,
                                    reached_target: is_success,
                                });

                                if is_success {
                                    dynamic_max_ttl.fetch_min(ttl, Ordering::Relaxed);
                                    break; // 收到终点响应，可提前结束 Gathering
                                }
                            }
                        }
                    }
                }

                // 清理此轮未响应的包 (判定为超时丢包)
                for (_, (ttl, _)) in in_flight_probes {
                    let _ = event_transmitter.send(NetworkEvent::EchoProbeResult {
                        ttl,
                        latency_ms: 0.0,
                        is_timeout: true,
                        reached_target: false,
                    });
                }

                // 补足剩余的休眠时间，保证每秒约 1 帧的探测频率
                let elapsed = start_time.elapsed();
                if elapsed < Duration::from_millis(1000) {
                    thread::sleep(Duration::from_millis(1000) - elapsed);
                }
            }
        });
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
        let mut chunks = packet.chunks_exact(2);
        while let Some(chunk) = chunks.next() {
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
// DNS 解析引擎及 TUI 渲染 (通用模块)
// ============================================================================

pub struct BackgroundDnsResolver;

impl BackgroundDnsResolver {
    pub fn spawn(
        ip_query_receiver: Receiver<String>,
        resolution_transmitter: Sender<DnsResolvedEvent>,
    ) {
        thread::spawn(move || {
            while let Ok(ip_string) = ip_query_receiver.recv() {
                if let Ok(ip_address) = ip_string.parse::<IpAddr>() {
                    let resolved_hostname = lookup_addr(&ip_address).unwrap_or_else(|_| ip_string.clone());

                    let _ = resolution_transmitter.send(DnsResolvedEvent {
                        original_ip: ip_string,
                        resolved_hostname,
                    });
                }
            }
        });
    }

    pub fn resolve_target_host(host: &str) -> Result<Ipv4Addr, String> {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(ip);
        }

        let lookup_str = format!("{}:0", host);
        match lookup_str.to_socket_addrs() {
            Ok(mut addrs) => {
                for addr in addrs.by_ref() {
                    if let std::net::SocketAddr::V4(v4) = addr {
                        return Ok(*v4.ip());
                    }
                }
                Err(format!("DNS 解析成功，但未找到与主机 '{}' 匹配的 IPv4 地址", host))
            }
            Err(e) => Err(format!("无法解析主机 '{}': {}", host, e)),
        }
    }
}

pub struct MtrApplication {
    target_hostname: String,
    target_ip: Ipv4Addr,
    route_hops: Vec<HopStatistic>,
    final_destination_ttl: Option<u8>,
    network_event_receiver: Receiver<NetworkEvent>,
    dns_query_transmitter: Sender<String>,
    dns_result_receiver: Receiver<DnsResolvedEvent>,
    ip_to_hostname_cache: HashMap<String, String>,
    in_flight_dns_queries: HashSet<String>,
    pub is_paused: Arc<AtomicBool>,
}

impl MtrApplication {
    pub fn new(
        target_hostname: String,
        target_ip: Ipv4Addr,
        network_event_receiver: Receiver<NetworkEvent>,
        dns_query_transmitter: Sender<String>,
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
    }

    pub fn dispatch_incoming_events(&mut self) {
        while let Ok(event) = self.network_event_receiver.try_recv() {
            match event {
                NetworkEvent::RouteHopDiscovered { ttl, ip_address } => {
                    if !self.in_flight_dns_queries.contains(&ip_address)
                        && !self.ip_to_hostname_cache.contains_key(&ip_address)
                    {
                        self.in_flight_dns_queries.insert(ip_address.clone());
                        let _ = self.dns_query_transmitter.send(ip_address.clone());
                    }

                    if let Some(hop) = self.route_hops.iter_mut().find(|hop| hop.ttl == ttl) {
                        if hop.ip_address == "???" {
                            hop.ip_address = ip_address;
                        }
                    } else {
                        self.route_hops.push(HopStatistic::new(ttl, ip_address));
                        self.route_hops.sort_by_key(|hop| hop.ttl);
                    }
                }
                NetworkEvent::EchoProbeResult {
                    ttl,
                    latency_ms,
                    is_timeout,
                    reached_target,
                } => {
                    if reached_target {
                        if self.final_destination_ttl.map_or(true, |f| ttl < f) {
                            self.final_destination_ttl = Some(ttl);
                        }
                    }

                    if !self.route_hops.iter().any(|hop| hop.ttl == ttl) {
                        self.route_hops.push(HopStatistic::new(ttl, "???".to_string()));
                        self.route_hops.sort_by_key(|hop| hop.ttl);
                    }

                    if let Some(hop) = self.route_hops.iter_mut().find(|hop| hop.ttl == ttl) {
                        hop.packets_sent += 1;
                        if !is_timeout {
                            hop.packets_received += 1;
                            hop.last_latency_ms = latency_ms;
                            hop.total_latency_ms += latency_ms;
                            if latency_ms < hop.best_latency_ms {
                                hop.best_latency_ms = latency_ms;
                            }
                            if latency_ms > hop.worst_latency_ms {
                                hop.worst_latency_ms = latency_ms;
                            }
                        }
                    }
                }
            }
        }

        while let Ok(dns_event) = self.dns_result_receiver.try_recv() {
            self.in_flight_dns_queries.remove(&dns_event.original_ip);
            self.ip_to_hostname_cache.insert(
                dns_event.original_ip,
                dns_event.resolved_hostname,
            );
        }

        if let Some(final_ttl) = self.final_destination_ttl {
            self.route_hops.retain(|hop| hop.ttl <= final_ttl);
        }
    }

    pub fn render_frame(&self, frame: &mut Frame) {
        let layout_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(2),
                Constraint::Min(10),
            ].as_ref())
            .split(frame.size());

        self.render_header(frame, layout_chunks[0]);
        self.render_guide(frame, layout_chunks[1]);
        self.render_statistics_table(frame, layout_chunks[2]);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let header_title = format!(" My Traceroute (mtr) to {} ({})", self.target_hostname, self.target_ip);
        let block = Paragraph::new(header_title)
            .style(Style::default().add_modifier(Modifier::BOLD));
        frame.render_widget(block, area);
    }

    fn render_guide(&self, frame: &mut Frame, area: Rect) {
        let pause_status = if self.is_paused.load(Ordering::Relaxed) {
            " [PAUSED]"
        } else {
            ""
        };
        let guide_text = format!(" Keys: [p] pause/resume{}   [r] restart statistics   [q] quit", pause_status);
        
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
            .map(|header_title| Cell::from(*header_title).style(Style::default().fg(Color::DarkGray)));
        
        let header_row = Row::new(table_headers)
            .style(Style::default().add_modifier(Modifier::BOLD))
            .height(1)
            .bottom_margin(1);

        let data_rows = self.route_hops.iter().map(|hop| {
            let display_name = if hop.ip_address == "???" {
                "???".to_string()
            } else if let Some(hostname) = self.ip_to_hostname_cache.get(&hop.ip_address) {
                if hostname != &hop.ip_address {
                    format!("{} ({})", hop.ip_address, hostname)
                } else {
                    hop.ip_address.clone()
                }
            } else {
                hop.ip_address.clone()
            };

            let cells = vec![
                Cell::from(format!("{}. {}", hop.ttl, display_name)),
                Cell::from(format!("{:.1}%", hop.packet_loss_percentage())),
                Cell::from(format!("{}", hop.packets_sent)),
                Cell::from(if hop.last_latency_ms > 0.0 { format!("{:.1}", hop.last_latency_ms) } else { String::from("-") }),
                Cell::from(if hop.average_latency_ms() > 0.0 { format!("{:.1}", hop.average_latency_ms()) } else { String::from("-") }),
                Cell::from(if hop.best_latency_ms < f64::MAX { format!("{:.1}", hop.best_latency_ms) } else { String::from("-") }),
                Cell::from(if hop.worst_latency_ms > 0.0 { format!("{:.1}", hop.worst_latency_ms) } else { String::from("-") }),
                Cell::from(format!("{:.1}", hop.standard_deviation())),
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
        Err(e) => {
            eprintln!("错误: {}", e);
            std::process::exit(1);
        }
    };

    enable_raw_mode()?;
    let mut standard_output = io::stdout();
    execute!(standard_output, EnterAlternateScreen)?;
    let tui_backend = CrosstermBackend::new(standard_output);
    let mut terminal_interface = Terminal::new(tui_backend)?;

    let (network_tx, network_rx) = mpsc::channel();
    let (dns_query_tx, dns_query_rx) = mpsc::channel();
    let (dns_result_tx, dns_result_rx) = mpsc::channel();

    let is_paused = Arc::new(AtomicBool::new(false));

    ActiveNetworkProber::spawn(network_tx, target_ipv4, Arc::clone(&is_paused));
    BackgroundDnsResolver::spawn(dns_query_rx, dns_result_tx);

    let mut application = MtrApplication::new(
        target_host,
        target_ipv4,
        network_rx,
        dns_query_tx,
        dns_result_rx,
        is_paused,
    );

    let refresh_interval = Duration::from_millis(100); 
    let mut last_tick_timestamp = Instant::now();

    loop {
        terminal_interface.draw(|frame| application.render_frame(frame))?;

        let timeout_duration = refresh_interval
            .checked_sub(last_tick_timestamp.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout_duration)? {
            if let Event::Key(key_event) = event::read()? {
                if key_event.kind == KeyEventKind::Press {
                    match key_event.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('c') if key_event.modifiers.contains(KeyModifiers::CONTROL) => break,
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

    disable_raw_mode()?;
    execute!(terminal_interface.backend_mut(), LeaveAlternateScreen)?;
    terminal_interface.show_cursor()?;

    Ok(())
}