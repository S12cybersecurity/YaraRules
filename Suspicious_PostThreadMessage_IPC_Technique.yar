rule Suspicious_PostThreadMessage_IPC_Technique {
    meta:
        description = "Detects binaries that use PostThreadMessage for potential inter-process communication (IPC). This uncommon API is sometimes abused by malware for stealthy cross-process messaging without creating named kernel objects."
        author = "0x12 Dark Development"
        date = "2025-12-24"
        reference = "Windows PostThreadMessage API usage for covert IPC"
        category = "suspicious_behavior"
        threat_level = "medium"  // Legitimate apps rarely use it for IPC; mostly UI or injection-related

    strings:
        $api1 = "PostThreadMessageA" ascii wide nocase
        $api2 = "PostThreadMessageW" ascii wide nocase
        $api3 = "GetMessageA" ascii wide nocase
        $api4 = "GetMessageW" ascii wide nocase
        $api5 = "PeekMessageA" ascii wide nocase
        $api6 = "PeekMessageW" ascii wide nocase
        $api7 = "DispatchMessageA" ascii wide nocase
        $api8 = "DispatchMessageW" ascii wide nocase

        // Common constants used with custom messages
        $const1 = "WM_USER" ascii wide
        $const2 = "WM_APP" ascii wide

    condition:
        uint16(0) == 0x5A4D  // PE executable
        and any of ($api1, $api2)  // Must use PostThreadMessage (key indicator)
        and 2 of ($api3, $api4, $api5, $api6, $api7, $api8)  // Message loop APIs usually present in receiver
        and any of ($const*)  // Custom message definitions (WM_USER + X or WM_APP + X)
}
