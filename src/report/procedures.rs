//! Manual validation procedures and command generator for identified amplification ports

/// Generate a terminal command to manually verify an amplification port finding.
pub fn get_manual_command(service: &str, port: u16, protocol: &str) -> String {
    match service.to_uppercase().as_str() {
        "QOTD" => "echo 'test' | nc -u -w 3 <IP> 17 | xxd".to_string(),
        "CHARGEN" => "echo 'test' | nc -u -w 3 <IP> 19 | xxd".to_string(),
        "DNS" => "dig +short -t ANY google.com @<IP>".to_string(),
        "TFTP" => "tftp <IP> -c get a.pdf".to_string(),
        "RPC" => "rpcinfo -T udp -p <IP>".to_string(),
        "NTP" => "printf '\\x16\\x02\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00' | nc -u -w 3 <IP> 123 | xxd".to_string(),
        "NETBIOS" => "printf '\\x00\\x01\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\x00\\x00\\x21\\x00\\x01' | nc -u -w 3 <IP> 137 | xxd".to_string(),
        "RIPV1" | "RIP" => "printf '\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x10' | nc -u -w 3 <IP> 520 | xxd".to_string(),
        "SNMP" => "snmpget -v 2c -c public <IP> iso.3.6.1.2.1.1.1.0".to_string(),
        "LDAP" | "CLDAP" => "printf '\\x30\\x25\\x02\\x01\\x01\\x63\\x20\\x04\\x00\\x0a\\x01\\x00\\x0a\\x01\\x00\\x02\\x01\\x00\\x02\\x01\\x00\\x01\\x01\\x00\\x87\\x0bobjectClass\\x30\\x00' | nc -u -w 3 <IP> 389 | xxd".to_string(),
        "SLP" => "printf '\\x02\\x01\\x00\\x00\\x36\\x20\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x02\\x65\\x6e\\x00\\x00\\x00\\x15\\x73\\x65\\x72\\x76\\x69\\x63\\x65\\x3a\\x73\\x65\\x72\\x76\\x69\\x63\\x65\\x2d\\x61\\x67\\x65\\x6e\\x74\\x00\\x07\\x64\\x65\\x66\\x61\\x75\\x6c\\x74\\x00\\x00\\x00\\x00' | nc -u -w 3 <IP> 427".to_string(),
        "SSDP" => "printf 'M-SEARCH * HTTP/1.1\\r\\nHost:239.255.255.250:1900\\r\\nST:upnp:rootdevice\\r\\nMan:\"ssdp:discover\"\\r\\nMX:3\\r\\n\\r\\n' | nc -u -w 3 <IP> 1900".to_string(),
        "ARMS" => "printf '\\x00\\x14\\x00\\x01\\x03' | nc -u -w 3 <IP> 3283 | xxd".to_string(),
        "MS-RDPEUDP" | "RDPEUDP" | "RDP-UDP" => "printf '\\x00\\x00\\x00\\x00\\x01\\x00\\x01\\x00\\x12\\x34\\x56\\x78\\xb0\\x04\\xb0\\x04' | nc -u -w 3 <IP> 3389 | xxd".to_string(),
        "WS-DISCOVERY" | "WSDISCOVERY" | "WS-DISCOVER" => "printf '\\x3c\\xaa\\x3e\\x0a' | nc -u -w 3 <IP> 3702 | xxd".to_string(),
        "SIP" | "VOIP" => "printf 'OPTIONS sip:ping@<IP> SIP/2.0\\r\\nVia: SIP/2.0/UDP <IP>:5060;branch=z9hG4bK-1\\r\\nMax-Forwards: 70\\r\\nFrom: <sip:ping@<IP>>;tag=1\\r\\nTo: <sip:ping@<IP>>\\r\\nCall-ID: 1@<IP>\\r\\nCSeq: 1 OPTIONS\\r\\nContent-Length: 0\\r\\n\\r\\n' | nc -u -w 3 <IP> 5060".to_string(),
        "MDNS" => "dig +short -p 5353 @<IP> -t PTR _services._dns-sd._udp.local".to_string(),
        "COAP" => "printf '\\x40\\x01\\x7d\\x70\\xbb\\x2e\\x77\\x65\\x6c\\x6c\\x2d\\x6b\\x6e\\x6f\\x77\\x6e\\x04\\x63\\x6f\\x72\\x65' | nc -u -w 3 <IP> 5683 | xxd".to_string(),
        "UBNT" => "printf '\\x01\\x00\\x00\\x00' | nc -u -w 3 <IP> 10001 | xxd".to_string(),
        "MEMCACHED" => "printf '\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00stats\\n' | nc -u -w 3 <IP> 11211".to_string(),
        "DVR-DHCPDISCOVER" | "DVR-DHCP" | "DVR" => format!("echo -ne '\\xff' | nc -u -w 2 <IP> {} | xxd", port),
        "MT4145" => "nc -z -v -w 3 <IP> 4145".to_string(),
        "MT5678" => "nc -z -v -w 3 <IP> 5678".to_string(),
        "HTTP" => "curl -I -m 3 http://<IP>".to_string(),
        "HTTPS" => "curl -kI -m 3 https://<IP>".to_string(),
        _ => {
            if protocol.to_lowercase() == "tcp" {
                format!("nc -z -v -w 3 <IP> {}", port)
            } else {
                format!("echo 'test' | nc -u -w 3 <IP> {} | xxd", port)
            }
        }
    }
}

