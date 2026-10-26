//! Raw packet capture for the guard: an AF_PACKET socket bound to one
//! interface, a classic BPF filter that keeps only inbound TCP SYNs, and the
//! IPv4/TCP parser. Detection state itself lives in `guard`.

use std::fs;
use std::io;
use std::path::Path;

use crate::util::ipv4_to_string;

pub const PACKET_HOST: u8 = 0;

/// A parsed inbound TCP SYN: `SYN` set, `ACK` clear, IPv4, unfragmented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SynPacket {
    pub src: u32,
    pub dst: u32,
    pub dst_port: u16,
}

const ETH_P_IP: u16 = 0x0800;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;

/// Pure parser over one Ethernet frame as delivered by AF_PACKET.
pub fn parse_inbound_tcp_syn(frame: &[u8]) -> Option<SynPacket> {
    if frame.len() < 14 + 20 + 20 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETH_P_IP {
        return None;
    }

    let version_ihl = frame[14];
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl = (version_ihl & 0x0F) as usize;
    if ihl < 5 {
        return None;
    }

    // Any fragmentation means the TCP header may not start here.
    if frame[20] & 0x3F != 0 {
        return None;
    }

    if frame[23] != 6 {
        return None; // not TCP
    }

    let total_len = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    if total_len < ihl * 4 + 20 {
        return None;
    }

    let tcp_start = 14 + ihl * 4;
    if frame.len() < tcp_start + 14 {
        return None;
    }

    let src = u32::from_be_bytes([frame[26], frame[27], frame[28], frame[29]]);
    let dst = u32::from_be_bytes([frame[30], frame[31], frame[32], frame[33]]);
    // TCP header: source port at +0, destination port at +2, flags at +13.
    let dst_port = u16::from_be_bytes([frame[tcp_start + 2], frame[tcp_start + 3]]);
    let flags = frame[tcp_start + 13];

    if flags & TCP_FLAG_SYN == 0 || flags & TCP_FLAG_ACK != 0 {
        return None;
    }

    if src == 0 || dst == 0 {
        return None;
    }

    Some(SynPacket { src, dst, dst_port })
}

/// Classic BPF that keeps only IPv4 TCP packets with SYN set and ACK clear.
/// Offsets mirror `parse_inbound_tcp_syn`; loads past the captured length
/// reject the packet inside the kernel, so the filter is its own bounds check.
pub fn syn_filter() -> Vec<libc::sock_filter> {
    const BPF_LD: u16 = 0x00;
    const BPF_ALU: u16 = 0x04;
    const BPF_JMP: u16 = 0x05;
    const BPF_RET: u16 = 0x06;
    const BPF_MISC: u16 = 0x07;
    const BPF_H: u16 = 0x08;
    const BPF_B: u16 = 0x10;
    const BPF_JEQ: u16 = 0x10;
    const BPF_JSET: u16 = 0x40;
    const BPF_ABS: u16 = 0x20;
    const BPF_IND: u16 = 0x40;
    const BPF_K: u16 = 0x00;
    const BPF_ADD: u16 = 0x00;
    const BPF_AND: u16 = 0x50;
    const BPF_LSH: u16 = 0x60;
    const BPF_TAX: u16 = 0x00;

    // Instruction indexes; jumps are computed as relative offsets from these.
    const IDX_LOAD_IHL: usize = 9;
    const IDX_REJECT: usize = 17;
    const IDX_ACCEPT: usize = 18;

    fn insn(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }
    // Classic BPF jumps are relative to the next instruction.
    fn rel(target: usize, from: usize) -> u8 {
        (target as isize - (from as isize + 1)).clamp(0, 255) as u8
    }
    let ldh_abs = |k: u32| insn(BPF_LD | BPF_H | BPF_ABS, 0, 0, k);
    let ldb_abs = |k: u32| insn(BPF_LD | BPF_B | BPF_ABS, 0, 0, k);
    let ldb_ind = |k: u32| insn(BPF_LD | BPF_B | BPF_IND, 0, 0, k);
    let jeq_at = |index: usize, k: u32, yes: usize, no: usize| {
        insn(
            BPF_JMP | BPF_JEQ | BPF_K,
            rel(yes, index),
            rel(no, index),
            k,
        )
    };
    let jset_at = |index: usize, k: u32, yes: usize, no: usize| {
        insn(
            BPF_JMP | BPF_JSET | BPF_K,
            rel(yes, index),
            rel(no, index),
            k,
        )
    };
    let alu_and = |k: u32| insn(BPF_ALU | BPF_AND | BPF_K, 0, 0, k);
    let alu_lsh = |k: u32| insn(BPF_ALU | BPF_LSH | BPF_K, 0, 0, k);
    let alu_add = |k: u32| insn(BPF_ALU | BPF_ADD | BPF_K, 0, 0, k);

    vec![
        ldh_abs(12),                                // 0: ethertype
        jeq_at(1, 0x0800, 2, IDX_REJECT),           // 1: IPv4?
        ldb_abs(14),                                // 2: version/ihl
        alu_and(0xf0),                              // 3: version
        jeq_at(4, 0x40, 5, IDX_REJECT),             // 4: IPv4
        ldb_abs(23),                                // 5: protocol
        jeq_at(6, 6, 7, IDX_REJECT),                // 6: TCP?
        ldb_abs(20),                                // 7: flags/fragment
        jset_at(8, 0x3f, IDX_REJECT, IDX_LOAD_IHL), // 8: fragments reject
        ldb_abs(14),                                // 9: ihl nibble
        alu_and(0x0f),                              // 10
        alu_lsh(2),                                 // 11: ihl*4
        alu_add(14),                                // 12: + ethernet header
        insn(BPF_MISC | BPF_TAX, 0, 0, 0),          // 13: X = TCP offset
        ldb_ind(13),                                // 14: TCP flags at X+13
        alu_and(0x12),                              // 15: SYN|ACK
        jeq_at(16, 0x02, IDX_ACCEPT, IDX_REJECT),   // 16: SYN only
        insn(BPF_RET | BPF_K, 0, 0, 0),             // 17: reject
        insn(BPF_RET | BPF_K, 0, 0, 0xFFFFFFFF),    // 18: accept
    ]
}

/// All IPv4 addresses of this host, in `Ipv4Addr` bit order
/// (127.0.0.1 → 0x7F000001).
pub fn own_ipv4s() -> Vec<u32> {
    let mut out = Vec::new();
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cursor = head;
        while !cursor.is_null() {
            let ifa = &*cursor;
            if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET {
                let addr = ifa.ifa_addr as *const libc::sockaddr_in;
                out.push(u32::from_be((*addr).sin_addr.s_addr));
            }
            cursor = ifa.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    out
}

/// The interface that owns the default route, from `/proc/net/route`.
pub fn default_interface() -> Option<String> {
    let text = fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 2 && fields[1] == "00000000" && !fields[0].is_empty() {
            return Some(fields[0].to_string());
        }
    }
    // No default route: fall back to the first real interface.
    let entries = fs::read_dir("/sys/class/net").ok()?;
    let mut names: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy() != "lo")
        .filter(|entry| entry.path().join("ifindex").try_exists().unwrap_or(false))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names.into_iter().next()
}

pub fn interface_exists(name: &str) -> bool {
    Path::new("/sys/class/net")
        .join(name)
        .join("ifindex")
        .try_exists()
        .unwrap_or(false)
}

fn interface_index(name: &str) -> Result<i32, String> {
    let text = fs::read_to_string(Path::new("/sys/class/net").join(name).join("ifindex"))
        .map_err(|_| format!("interface '{name}' does not exist"))?;
    text.trim()
        .parse::<i32>()
        .map_err(|_| format!("cannot determine the index of interface '{name}'"))
}

/// Checks whether this process can open a raw packet socket at all.
pub fn probe_raw_socket() -> Result<(), String> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::htons(libc::ETH_P_ALL as u16) as i32,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return Err(match error.raw_os_error() {
            Some(libc::EPERM) | Some(libc::EACCES) => {
                "permission denied: the guard needs root or CAP_NET_RAW".to_string()
            }
            _ => format!("cannot open a raw packet socket: {error}"),
        });
    }
    unsafe { libc::close(fd) };
    Ok(())
}

/// A raw socket bound to one interface that yields only inbound TCP SYNs.
pub struct PacketSocket {
    fd: i32,
}

impl PacketSocket {
    pub fn open(interface: &str) -> Result<Self, String> {
        probe_raw_socket().map_err(|message| format!("cannot watch '{interface}': {message}"))?;
        let ifindex = interface_index(interface)?;

        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::htons(libc::ETH_P_ALL as u16) as i32,
            )
        };
        if fd < 0 {
            return Err(format!(
                "cannot open a raw packet socket: {}",
                io::Error::last_os_error()
            ));
        }

        let address = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: libc::htons(libc::ETH_P_ALL as u16),
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let bound = unsafe {
            libc::bind(
                fd,
                &address as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if bound < 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(format!("cannot bind to '{interface}': {error}"));
        }

        let timeout = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
        }

        let filter = syn_filter();
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        let attached = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &program as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::sock_fprog>() as u32,
            )
        };
        if attached < 0 {
            // The kernel filter is an optimization; userspace parsing still
            // drops everything that is not an inbound SYN.
            crate::util::warn("cannot attach the packet filter; parsing in userspace");
        }

        Ok(Self { fd })
    }

    /// `Ok(None)` on receive timeout, which the caller uses for periodic work.
    pub fn recv(&self, buffer: &mut [u8]) -> Result<Option<(u8, usize)>, String> {
        let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut from_len = std::mem::size_of::<libc::sockaddr_ll>() as u32;
        let read = unsafe {
            libc::recvfrom(
                self.fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
                &mut from as *mut _ as *mut libc::sockaddr,
                &mut from_len,
            )
        };
        if read < 0 {
            let error = io::Error::last_os_error();
            return match error.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Ok(None),
                io::ErrorKind::Interrupted => Ok(None),
                _ => Err(format!("packet receive failed: {error}")),
            };
        }
        Ok(Some((from.sll_pkttype, read as usize)))
    }
}

impl Drop for PacketSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

#[allow(dead_code)]
pub fn describe_addr(addr: u32) -> String {
    ipv4_to_string(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(payload_tcp_flags: u8, protocol: u8, version_ihl: u8) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst mac
        frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src mac
        frame.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
        let ihl = (version_ihl & 0x0F) as usize;
        frame.push(version_ihl);
        frame.push(0x00); // tos
        frame.extend_from_slice(&[0x00, (40 + (ihl as u16 - 5) * 4) as u8]); // total len
        frame.extend_from_slice(&[0x00, 0x00]); // id
        frame.extend_from_slice(&[0x00, 0x00]); // flags/frag: none
        frame.push(64); // ttl
        frame.push(protocol);
        frame.extend_from_slice(&[0x00, 0x00]); // checksum
        frame.extend_from_slice(&[192, 168, 1, 250]); // src
        frame.extend_from_slice(&[192, 168, 1, 42]); // dst
        for _ in 5..ihl {
            frame.extend_from_slice(&[0x00; 4]);
        }
        frame.extend_from_slice(&[0x1f, 0x90]); // src port 8080
        frame.extend_from_slice(&[0x00, 0x16]); // dst port 22
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
        frame.push(0x50); // data offset
        frame.push(payload_tcp_flags);
        frame.extend_from_slice(&[0xff, 0xff]); // window
        frame.extend_from_slice(&[0x00, 0x00]); // checksum
        frame.extend_from_slice(&[0x00, 0x00]); // urgent
        frame
    }

    #[test]
    fn parses_a_plain_syn() {
        let frame = frame(TCP_FLAG_SYN, 6, 0x45);
        let packet = parse_inbound_tcp_syn(&frame).expect("syn parses");
        assert_eq!(packet.dst_port, 22);
        assert_eq!(ipv4_to_string(packet.src), "192.168.1.250");
        assert_eq!(ipv4_to_string(packet.dst), "192.168.1.42");
    }

    #[test]
    fn rejects_non_syn_and_non_tcp() {
        let syn_ack = frame(TCP_FLAG_SYN | TCP_FLAG_ACK, 6, 0x45);
        assert!(parse_inbound_tcp_syn(&syn_ack).is_none());
        let ack = frame(TCP_FLAG_ACK, 6, 0x45);
        assert!(parse_inbound_tcp_syn(&ack).is_none());
        let udp = frame(TCP_FLAG_SYN, 17, 0x45);
        assert!(parse_inbound_tcp_syn(&udp).is_none());
        let arp = frame(TCP_FLAG_SYN, 6, 0x55);
        assert!(parse_inbound_tcp_syn(&arp).is_none(), "ihl < 5");
        let ipv6 = frame(TCP_FLAG_SYN, 6, 0x65);
        assert!(parse_inbound_tcp_syn(&ipv6).is_none(), "version 6");
    }

    #[test]
    fn rejects_fragments_and_short_frames() {
        let mut fragmented = frame(TCP_FLAG_SYN, 6, 0x45);
        fragmented[20] = 0x20; // more fragments
        assert!(parse_inbound_tcp_syn(&fragmented).is_none());

        let short = frame(TCP_FLAG_SYN, 6, 0x45);
        assert!(parse_inbound_tcp_syn(&short[..20]).is_none());
    }

    #[test]
    fn filter_has_expected_shape() {
        let filter = syn_filter();
        assert_eq!(filter.len(), 19);
        assert_eq!(filter[0].code & 0x28, 0x28, "first load is ldh");
        assert_eq!(filter[0].k, 12);
        assert_eq!(filter[17].k, 0, "reject returns zero");
        assert_eq!(filter[18].k, 0xFFFFFFFF, "accept returns all bytes");
    }

    /// A tiny classic-BPF interpreter so the filter's semantics are tested
    /// against the same frames the userspace parser sees.
    fn run_filter(filter: &[libc::sock_filter], frame: &[u8]) -> bool {
        let mut pc: usize = 0;
        let mut a: u32 = 0;
        let mut x: u32 = 0;
        for _ in 0..256 {
            if pc >= filter.len() {
                return false;
            }
            let insn = &filter[pc];
            let code = insn.code;
            let class = code & 0x07;
            let size = code & 0x18;
            let mode = code & 0xe0;
            let op = code & 0xf0;
            match class {
                0x00 => {
                    // BPF_LD
                    let load: Option<u32> = match mode {
                        0x20 => match size {
                            0x00 => frame
                                .get(insn.k as usize..insn.k as usize + 4)
                                .map(|slice| u32::from_be_bytes(slice.try_into().unwrap())),
                            0x08 => frame
                                .get(insn.k as usize)
                                .map(|byte| u16::from_be_bytes([*byte, 0]) as u32),
                            _ => frame.get(insn.k as usize).map(|byte| *byte as u32),
                        },
                        0x40 => {
                            let index = x as usize + insn.k as usize;
                            frame.get(index).map(|byte| *byte as u32)
                        }
                        _ => None,
                    };
                    match load {
                        Some(value) => a = value,
                        None => return false, // out of bounds → rejected
                    }
                }
                0x04 => match op {
                    0x00 => a = a.wrapping_add(insn.k),
                    0x50 => a &= insn.k,
                    0x60 => a <<= insn.k,
                    _ => panic!("unsupported alu op {op:#x}"),
                },
                0x05 => {
                    let taken = match op {
                        0x10 => a == insn.k,
                        0x40 => a & insn.k != 0,
                        _ => panic!("unsupported jmp op {op:#x}"),
                    };
                    pc += if taken {
                        insn.jt as usize
                    } else {
                        insn.jf as usize
                    };
                }
                0x06 => return insn.k != 0,
                0x07 => x = a,
                _ => panic!("unsupported class {class:#x}"),
            }
            pc += 1;
        }
        false
    }

    #[test]
    fn bpf_filter_agrees_with_the_userspace_parser() {
        let filter = syn_filter();
        let cases: Vec<(u8, u8, u8, bool)> = vec![
            // (tcp flags, protocol, version/ihl, should the filter accept?)
            (TCP_FLAG_SYN, 6, 0x45, true),
            (TCP_FLAG_SYN | TCP_FLAG_ACK, 6, 0x45, false),
            (TCP_FLAG_ACK, 6, 0x45, false),
            (TCP_FLAG_SYN, 17, 0x45, false), // UDP
            (TCP_FLAG_SYN, 6, 0x55, false),  // ihl < 5
            (TCP_FLAG_SYN, 6, 0x65, false),  // version 6
            (0x00, 0, 0x45, false),          // arp-ish payload, ethertype set by builder? see below
        ];
        for (flags, protocol, version_ihl, accept) in cases {
            let mut bytes = frame(flags, protocol, version_ihl);
            if protocol == 0 {
                // make it a non-IPv4 ethertype
                bytes[12] = 0x08;
                bytes[13] = 0x06;
            }
            let parsed = parse_inbound_tcp_syn(&bytes);
            let filtered = run_filter(&filter, &bytes);
            assert_eq!(
                filtered, accept,
                "filter verdict for flags={flags:#x} proto={protocol} vihl={version_ihl:#x}"
            );
            assert_eq!(
                parsed.is_some(),
                accept,
                "parser verdict for flags={flags:#x} proto={protocol} vihl={version_ihl:#x}"
            );
        }

        // A fragmented packet: the builder forces frag=0, so patch it.
        let mut fragmented = frame(TCP_FLAG_SYN, 6, 0x45);
        fragmented[20] = 0x20;
        assert!(parse_inbound_tcp_syn(&fragmented).is_none());
        assert!(!run_filter(&filter, &fragmented), "fragments reject");
    }

    #[test]
    fn own_ips_include_loopback() {
        let ips = own_ipv4s();
        assert!(!ips.is_empty(), "loopback must be present on Linux");
        assert!(ips.contains(&0x7F000001), "127.0.0.1 as bits");
    }

    #[test]
    fn default_interface_is_sane() {
        if let Some(name) = default_interface() {
            assert!(!name.is_empty());
            assert!(interface_exists(&name));
        }
    }
}
