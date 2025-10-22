rule dns_txt_c2_tunnel
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects DNS TXT-based command-and-control / DNS tunneling patterns: exec + Winsock network calls + TXT markers + encoded subdomains."
        version = "1.0"
        reference = "Generic detection for DNS TXT C2 / DNS tunneling"
        tlp = "WHITE"

    strings:
        /* execution helpers (source or imported symbols) */
        $s_popen        = "_popen(" ascii nocase
        $s_system       = "system(" ascii nocase
        $s_win_exec     = "CreateProcessA(" ascii nocase

        /* Winsock / UDP networking calls or initialization */
        $s_WSAStartup   = "WSAStartup(" ascii nocase
        $s_sendto       = "sendto(" ascii nocase
        $s_recvfrom     = "recvfrom(" ascii nocase
        $s_inet_pton    = "inet_pton(" ascii nocase
        $s_setsockopt   = "setsockopt(" ascii nocase

        /* DNS TXT markers:
           - binary QTYPE for TXT is 0x0010 (00 10)
           - common QTYPE+QCLASS tail for TXT+IN: 00 10 00 01
        */
        $h_qtype_txt    = { 00 10 }                /* TXT type (binary) */
        $h_qtype_txt_in = { 00 10 00 01 }          /* TXT + IN (binary) */

        /* textual markers and domain-like patterns often used to carry data */
        $s_txt_literal  = "TXT" ascii nocase
        $s_qname_label  = /([a-z0-9\-]{1,63}\.){2,}[a-z]{2,}/ nocase

    condition:
        // Require evidence of: (1) local command execution capability, (2) Winsock/UDP usage,
        // and (3) DNS TXT indicators OR domain-like encoded subdomains.
        (
            ( $s_popen or $s_system or $s_win_exec ) and
            ( $s_WSAStartup or $s_sendto or $s_recvfrom or $s_inet_pton or $s_setsockopt ) and
            ( $h_qtype_txt or $h_qtype_txt_in or $s_txt_literal or $s_qname_label )
        )
        // limit to reasonable file size to reduce noise from very large resources
        and filesize < 10MB
}
