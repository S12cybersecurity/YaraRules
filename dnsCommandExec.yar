rule DNS_Tunnel_Client_Technique {
    meta:
        author = "0x12 Dark Development"
        description = "Detects DNS tunneling client techniques commonly used for C2 communication"
        date = "2023-12-01"
        severity = "High"
        reference = "Technique T1071.004 - DNS Tunneling"

    strings:
        // DNS packet construction patterns
        $dns_header1 = { ?? ?? 01 00 00 01 00 00 00 00 00 00 }  // Standard DNS query header
        $dns_header2 = { ?? ?? 01 20 00 01 00 00 00 00 00 00 }  // DNS query with recursion
        $dns_txt_record = { 00 10 00 01 }  // TXT record type (16) and IN class (1)
        $dns_type_txt = "00 10"  // TXT record type
        $dns_type_a = "00 01"    // A record type
        
        // Network function imports (Windows)
        $socket_import = "socket" wide ascii
        $sendto_import = "sendto" wide ascii
        $recvfrom_import = "recvfrom" wide ascii
        $ws2_32 = "ws2_32.dll" wide ascii
        
        // Common DNS tunneling patterns
        $domain_encoding1 = /[a-zA-Z0-9]{16,}\.(com|net|org|info)/
        $domain_encoding2 = /[a-zA-Z0-9_-]{20,}\.(com|net|org)/
        $base64_like = /[A-Za-z0-9+/]{32,}={0,2}\./
        
        // Program behavior strings
        $dns_port = "53" wide ascii
        $timeout_set = "SO_RCVTIMEO" wide ascii
        $udp_socket = "SOCK_DGRAM" wide ascii

    condition:
        // High confidence: DNS packet construction + network functions
        ( 
            (2 of ($dns_header*)) and 
            (2 of ($socket_import, $sendto_import, $recvfrom_import)) and
            (1 of ($dns_txt_record, $dns_type_txt, $dns_type_a))
        )
        or
        // Medium confidence: Suspicious domain patterns + network functions
        (
            (1 of ($domain_encoding*)) and
            (2 of ($socket_import, $sendto_import, $recvfrom_import)) and
            ($ws2_32 in (0..500))
        )
        or
        // Behavioral pattern: UDP socket + timeout + DNS port
        (
            ($udp_socket and $timeout_set and $dns_port) and
            (1 of ($socket_import, $sendto_import, $recvfrom_import))
        )
}
