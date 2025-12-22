rule Win_ProcInj_ThreadNameCalling_General {
    meta:
        author = "0x12 Dark Development"
        description = "Detects process injection tools or malware using the Thread Name-Calling technique (abusing SetThreadDescription/GetThreadDescription + APC for remote code transfer/execution)"
        date = "2025-12-22"
        reference = "https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/"
        technique = "T1055 Process Injection - Thread Name Abuse"
        mitre_att = "T1055"
        tlp = "WHITE"

    strings:
        // High-level APIs
        $api1 = "SetThreadDescription" ascii wide
        $api2 = "GetThreadDescription" ascii wide

        // Low-level variants (ThreadNameInformation class)
        $nt1 = "NtSetInformationThread" ascii wide
        $nt2 = "NtQueryInformationThread" ascii wide
        $class = { 00 00 00 00 26 00 00 00 } // ThreadNameInformation = 0x26 (little-endian DWORD)

        // APC queuing APIs commonly used in this technique
        $apc1 = "QueueUserAPC" ascii wide
        $apc2 = "NtQueueApcThread" ascii wide
        $apc3 = "NtQueueApcThreadEx" ascii wide

        // Optional: VirtualProtect for making payload executable
        $vp = "VirtualProtectEx" ascii wide

    condition:
        // Must be a PE file
        uint16(0) == 0x5A4D and

        // Core indicators: thread description APIs + APC queuing
        (1 of ($api*) or all of ($nt*) or $class) and
        any of ($apc*)

        // Optional boost: presence of remote memory protection change (common after payload transfer)
        or $vp
}
