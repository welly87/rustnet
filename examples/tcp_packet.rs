extern crate pnet;

use std::net::Ipv4Addr;

use pnet_packet::Packet;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption, ipv4_checksum, TcpPacket};

use pnet::datalink::{Channel, MacAddr, NetworkInterface};

use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;

fn send_tcp_packet(interface: NetworkInterface, target_ip: Ipv4Addr) {
    // let source_ip = interface
    //     .ips
    //     .iter()
    //     .find(|ip| ip.is_ipv4())
    //     .map(|ip| match ip.ip() {
    //         IpAddr::V4(ip) => ip,
    //         _ => unreachable!(),
    //     })
    //     .unwrap();
        
    let (mut sender, mut receiver) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 70];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let tcp_packet = create_tcp_packet();
    ethernet_packet.set_payload(&tcp_packet);

    sender
        .send_to(ethernet_packet.packet(), None)
        .unwrap()
        .unwrap();

    println!("Sent TCP request");

    while let buf = receiver.next().unwrap()  {

        let buf = receiver.next().unwrap();

        let tcp = TcpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).unwrap();

        println!("Received reply {}", tcp.packet().len());
    }
}

fn create_tcp_packet() -> [u8; 56] {

    const IPV4_HEADER_LEN: usize = 20;
    const TCP_HEADER_LEN: usize = 32;
    const TEST_DATA_LEN: usize = 4;

    let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TEST_DATA_LEN];

    let ipv4_source = Ipv4Addr::new(192, 168, 2, 1);

    let ipv4_destination = Ipv4Addr::new(192, 168, 111, 51);
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(ipv4_source);
        ip_header.set_destination(ipv4_destination);
    }

    // Set data
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN] = 't' as u8;
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 1] = 'e' as u8;
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 2] = 's' as u8;
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 3] = 't' as u8;

    let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();

    tcp_header.set_source(49511);
    tcp_header.set_destination(9000);
    tcp_header.set_sequence(0x9037d2b8);
    tcp_header.set_acknowledgement(0x944bb276);

    tcp_header.set_flags(TcpFlags::PSH | TcpFlags::ACK);
    tcp_header.set_window(4015);

    tcp_header.set_data_offset(8);

    let ts = TcpOption::timestamp(743951781, 44056978);
    tcp_header.set_options(&vec![TcpOption::nop(), TcpOption::nop(), ts]);

    let checksum = ipv4_checksum(&tcp_header.to_immutable(), &ipv4_source, &ipv4_destination);
    tcp_header.set_checksum(checksum);

    packet
}

fn main() {
    let iface_name = "ens5";
    let target_ip = Ipv4Addr::new(52, 198, 87, 207);

    let interfaces = pnet::datalink::interfaces();
    
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == iface_name)
        .unwrap();

    let _source_mac = interface.mac.unwrap();

    send_tcp_packet(interface, target_ip);
}
