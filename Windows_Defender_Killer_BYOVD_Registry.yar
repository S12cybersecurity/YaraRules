rule Windows_Defender_Killer_BYOVD_Registry
{
    meta:
        description = "Detects tools combining BYOVD kernel-level process termination with Registry-based Defender disabling."
        author = "0x12 Dark Development"
        technique = "BYOVD + Registry Sabotage"
        date = "2026-04-07"
        severity = "Critical"

    strings:
        // Registry paths and values for disabling Defender
        $reg_path_1 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide
        $reg_path_2 = "Real-Time Protection" ascii wide
        $val_1 = "DisableAntiSpyware" ascii wide
        $val_2 = "DisableRealtimeMonitoring" ascii wide
        $val_3 = "DisableBehaviorMonitoring" ascii wide
        $val_4 = "DisableScanOnRealtimeEnable" ascii wide
        $val_5 = "DisableOnAccessProtection" ascii wide
        $val_6 = "DisableIOAVProtection" ascii wide

        // Target process
        $target_proc = "MsMpEng.exe" ascii wide

        // Driver loading indicators
        $priv_load = "SeLoadDriverPrivilege" ascii wide
        $api_ntload = "NtLoadDriver" ascii
        $api_ntunload = "NtUnloadDriver" ascii
        $api_rtlinit = "RtlInitUnicodeString" ascii

        // Service/Driver setup strings
        $svc_path = "SYSTEM\\CurrentControlSet\\Services\\" ascii wide
        $sys_ext = ".sys" ascii wide
        
        // Potential IOCTL for process termination (from the code provided)
        // 0xB822200C in little-endian: 0C 20 22 B8
        $ioctl_kill = { 0C 20 22 B8 }

    condition:
        uint16(0) == 0x5A4D and // PE File
        (
            // Logic: Must have Defender registry keys AND signs of driver management
            (all of ($reg_path*) and 3 of ($val_*)) and
            (
                $target_proc and 
                (2 of ($api_nt*) or $priv_load or $ioctl_kill)
            )
        ) or (
            // Secondary logic: High concentration of Defender sabotage strings in a single binary
            all of ($val_*) and $target_proc
        )
}
