//! Static definitions of default amplification ports
//!
//! Contains default ports (UDP and TCP) monitored by AmpScan,
//! aligned with Shadowserver, CISA, and NETSCOUT threat research.

pub struct DefaultPortDef {
    pub port: u16,
    pub protocol: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub probe_type: &'static str,
    pub payload: &'static [u8],
}

pub const DEFAULT_PORTS: &[DefaultPortDef] = &[
    // ── UDP probes ──────────────────────────────────────────────────
    DefaultPortDef {
        port: 17,
        protocol: "udp",
        name: "QOTD",
        description: "Quote of the Day - legacy service that responds to any packet, used for DDoS amplification",
        probe_type: "udp_payload",
        payload: &[],
    },
    DefaultPortDef {
        port: 19,
        protocol: "udp",
        name: "CHARGEN",
        description: "Character Generator - legacy service that generates a character stream, used for DDoS amplification",
        probe_type: "udp_payload",
        payload: &[],
    },
    DefaultPortDef {
        port: 53,
        protocol: "udp",
        name: "DNS",
        description: "Domain Name System - open resolvers can amplify traffic up to 54x",
        probe_type: "dns",
        payload: &[],
    },
    DefaultPortDef {
        port: 69,
        protocol: "udp",
        name: "TFTP",
        description: "Trivial File Transfer Protocol - exposed TFTP servers allow file extraction and amplification",
        probe_type: "tftp",
        payload: &[],
    },
    DefaultPortDef {
        port: 111,
        protocol: "udp",
        name: "RPC",
        description: "Remote Procedure Call Portmapper - exposure allows service enumeration and amplification",
        probe_type: "rpc",
        payload: &[],
    },
    DefaultPortDef {
        port: 123,
        protocol: "udp",
        name: "NTP",
        description: "Network Time Protocol - servers with monlist/readvar amplify traffic up to 556x",
        probe_type: "ntp",
        payload: &[],
    },
    DefaultPortDef {
        port: 137,
        protocol: "udp",
        name: "NETBIOS",
        description: "NetBIOS Name Service - exposure reveals network information and allows amplification",
        probe_type: "netbios",
        payload: &[],
    },
    DefaultPortDef {
        port: 520,
        protocol: "udp",
        name: "RIPv1",
        description: "Routing Information Protocol v1 - legacy routing daemon that amplifies traffic up to 30x",
        probe_type: "ripv1",
        payload: &[],
    },
    DefaultPortDef {
        port: 161,
        protocol: "udp",
        name: "SNMP",
        description: "Simple Network Management Protocol - 'public' community exposes data and amplifies up to 6.3x",
        probe_type: "snmp",
        payload: &[],
    },
    DefaultPortDef {
        port: 389,
        protocol: "udp",
        name: "LDAP",
        description: "CLDAP - Connectionless LDAP used for massive amplification up to 70x",
        probe_type: "ldap",
        payload: &[],
    },
    DefaultPortDef {
        port: 427,
        protocol: "udp",
        name: "SLP",
        description: "Service Location Protocol - used for service amplification up to 2200x",
        probe_type: "udp_payload",
        payload: &[
            0x02, 0x01, 0x00, 0x00, 0x36, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x02, 0x65, 0x6e, 0x00, 0x00, 0x00, 0x15, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
            0x65, 0x3a, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x61, 0x67, 0x65,
            0x6e, 0x74, 0x00, 0x07, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x00, 0x00,
            0x00, 0x00,
        ],
    },
    DefaultPortDef {
        port: 1900,
        protocol: "udp",
        name: "SSDP",
        description: "Simple Service Discovery Protocol - UPnP amplifies traffic up to 30x",
        probe_type: "ssdp",
        payload: &[],
    },
    DefaultPortDef {
        port: 3283,
        protocol: "udp",
        name: "ARMS",
        description: "Apple Remote Management Service - amplification via Apple Remote Desktop",
        probe_type: "udp_payload",
        payload: &[0x00, 0x14, 0x00, 0x01, 0x03],
    },
    DefaultPortDef {
        port: 3389,
        protocol: "udp",
        name: "MS-RDPEUDP",
        description: "Microsoft RDP UDP Extension - vulnerable to massive reflection/amplification DDoS up to 85.9x",
        probe_type: "rdpeudp",
        payload: &[],
    },
    DefaultPortDef {
        port: 3702,
        protocol: "udp",
        name: "WS-DISCOVERY",
        description: "Web Services Dynamic Discovery - SOAP/XML amplification up to 153x",
        probe_type: "udp_payload",
        payload: &[0x3C, 0xAA, 0x3E, 0x0A],
    },
    DefaultPortDef {
        port: 5060,
        protocol: "udp",
        name: "SIP",
        description: "Session Initiation Protocol - exposed PBX/VoIP responds to OPTIONS queries, amplifying up to 30x",
        probe_type: "sip",
        payload: &[],
    },
    DefaultPortDef {
        port: 5353,
        protocol: "udp",
        name: "mDNS",
        description: "Multicast DNS - open mDNS resolvers amplify up to 4.7x",
        probe_type: "mdns",
        payload: &[],
    },
    DefaultPortDef {
        port: 5683,
        protocol: "udp",
        name: "CoAP",
        description: "Constrained Application Protocol - IoT devices amplify up to 34x",
        probe_type: "udp_payload",
        payload: &[
            0x40, 0x01, 0x7d, 0x70, 0xbb, 0x2e, 0x77, 0x65, 0x6c, 0x6c, 0x2d, 0x6b, 0x6e,
            0x6f, 0x77, 0x6e, 0x04, 0x63, 0x6f, 0x72, 0x65,
        ],
    },
    DefaultPortDef {
        port: 10001,
        protocol: "udp",
        name: "UBNT",
        description: "Ubiquiti Discovery Protocol - exposed Ubiquiti devices on the network",
        probe_type: "udp_payload",
        payload: &[0x01, 0x00, 0x00, 0x00],
    },
    DefaultPortDef {
        port: 11211,
        protocol: "udp",
        name: "MEMCACHED",
        description: "Memcached - massive amplification up to 51000x, extremely dangerous",
        probe_type: "memcached",
        payload: &[],
    },
    DefaultPortDef {
        port: 37810,
        protocol: "udp",
        name: "DVR-DHCPDiscover",
        description: "DVR DHCP Discovery - exposed cameras and DVRs responding to discovery",
        probe_type: "udp_payload",
        payload: &[0xFF],
    },
    // ── TCP probes ──────────────────────────────────────────────────
    DefaultPortDef {
        port: 4145,
        protocol: "tcp",
        name: "MT4145",
        description: "MikroTik open SOCKS proxy - may indicate a compromised MikroTik device",
        probe_type: "tcp_connect",
        payload: &[],
    },
    DefaultPortDef {
        port: 5678,
        protocol: "tcp",
        name: "MT5678",
        description: "MikroTik Meris botnet - indicates possible Meris botnet infection (DDoS)",
        probe_type: "tcp_connect",
        payload: &[],
    },
];

use crate::db::models::Port;

/// Convert static DEFAULT_PORTS into a Vec of Port models for zero-DB execution
pub fn get_default_ports() -> Vec<Port> {
    DEFAULT_PORTS
        .iter()
        .enumerate()
        .map(|(i, def)| Port {
            id: (i + 1) as i64,
            port: def.port,
            protocol: def.protocol.to_string(),
            name: def.name.to_string(),
            description: def.description.to_string(),
            probe_type: def.probe_type.to_string(),
            probe_payload: if def.payload.is_empty() {
                None
            } else {
                Some(def.payload.to_vec())
            },
            enabled: true,
            created_at: String::new(),
            updated_at: String::new(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_default_ports_completeness() {
        let ports = get_default_ports();
        assert_eq!(ports.len(), 23);
        for p in &ports {
            assert!(p.enabled);
            assert!(!p.name.is_empty());
            assert!(p.protocol == "udp" || p.protocol == "tcp");
        }
    }
}
