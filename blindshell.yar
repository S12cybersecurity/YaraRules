rule 0x12_DarkDevelopment_BindShell_Technique
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects characteristic patterns of a bind/bind-style shell on Windows (Winsock + command execution). Not tied to one exact source file."
        date = "2025-10-07"
        reference = "Detection rule for listening-socket + remote-command execution patterns"
        severity = "medium"
        tags = "networking", "winsock", "bind-shell", "remote-exec", "suspicious"

    strings:
        /*
         * Source-code / ASCII signatures commonly seen in C/C++ examples
         */
        $s_wsa_start     = "WSAStartup" nocase
        $s_socket        = "socket" nocase
        $s_bind          = "bind" nocase
        $s_listen        = "listen" nocase
        $s_accept        = "accept" nocase
        $s_recv          = "recv" nocase
        $s_inaddr_any    = "INADDR_ANY" nocase
        $s_htons         = "htons" nocase
        $s_system_call   = "system" nocase
        $s_prag_winsock  = "ws2_32.lib" nocase
        $s_pragma_comment = "#pragma comment(lib" nocase

        /*
         * Import names commonly present in compiled Windows binaries
         * (these also appear as ASCII text in import table)
         */
        $imp_ws2         = "ws2_32.dll" nocase
        $imp_socket      = "socket" nocase
        $imp_bind_imp    = "bind" nocase
        $imp_listen_imp  = "listen" nocase
        $imp_accept_imp  = "accept" nocase
        $imp_recv_imp    = "recv" nocase
        $imp_send_imp    = "send" nocase
        $imp_wsa_start   = "WSAStartup" nocase
        $imp_msvcrt      = "msvcrt.dll" nocase
        $imp_system_imp  = "system" nocase
        $imp_CreateProc  = "CreateProcessA" nocase
        $imp_WinExec     = "WinExec" nocase

        /*
         * A loose regex to capture the sequence WSAStartup -> socket -> bind/listen/accept in source files.
         * DOTALL-like behavior simulated by allowing up to 800 chars between tokens.
         */
        $seq_ws = /WSAStartup(.{0,800}?)socket(.{0,800}?)(bind|listen|accept)/si

    condition:
        (
            /* Heuristic A: Source-like patterns (C/C++ code or embedded strings) */
            (
                ($s_wsa_start and $s_socket and ($s_bind or $s_listen or $s_accept) and ($s_recv or $s_send))
                or $seq_ws
            )
        )
        or
        (
            /* Heuristic B: Compiled PE with imports that match Winsock + exec APIs.
               Require ws2_32 import + at least 3 socket-related imports AND at least one exec-like import */
            (
                any of ($imp_ws2) and
                (
                    ( $imp_socket and $imp_bind_imp and ($imp_listen_imp or $imp_accept_imp) and $imp_recv_imp )
                    or
                    ( $imp_wsa_start and $imp_socket and $imp_bind_imp and $imp_accept_imp )
                )
                and
                ( $imp_system_imp or $imp_CreateProc or $imp_WinExec or $imp_msvcrt )
            )
        )
}
