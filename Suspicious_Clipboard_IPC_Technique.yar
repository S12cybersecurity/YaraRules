rule Suspicious_Clipboard_IPC_Technique {
    meta:
        description = "Detects binaries that manipulate the Windows clipboard in a way often used for inter-process communication (IPC), such as writing and reading text data via clipboard APIs. This can be abused by malware for covert data exchange between processes."
        author = "0x12 Dark Development"
        date = "2025-12-24"
        reference = "Windows Clipboard API usage for IPC"
        category = "suspicious_behavior"
        threat_level = "medium"  // Common in legitimate apps too, but combined usage can be suspicious

    strings:
        $api1 = "OpenClipboard" ascii wide nocase
        $api2 = "CloseClipboard" ascii wide nocase
        $api3 = "EmptyClipboard" ascii wide nocase
        $api4 = "SetClipboardData" ascii wide nocase
        $api5 = "GetClipboardData" ascii wide nocase
        $api6 = "GlobalAlloc" ascii wide nocase
        $api7 = "GlobalLock" ascii wide nocase
        $format1 = "CF_TEXT" ascii wide
        $format2 = "CF_UNICODETEXT" ascii wide

    condition:
        uint16(0) == 0x5A4D  // PE executable
        and 3 of ($api*)  // At least 3 clipboard-related APIs
        and ($api4 or $api5)  // Must include set or get data
        and ($api1 and $api2)  // Open and close are usually paired
        and any of ($format*)  // Targets text formats
        and ($api6 or $api7)  // Memory allocation/locking for data handling
}
