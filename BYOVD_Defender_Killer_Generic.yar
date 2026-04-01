rule BYOVD_Defender_Killer_Generic {
    meta:
        description = "Detects tools using BYOVD techniques to terminate Windows Defender processes"
        author = "0x12 Dark Development"
        date = "2026-04-01"
        technique = "T1068 - Exploitation for Privilege Escalation"
        reference = "CVE-2026-0828"
        severity = "Critical"

    strings:
        // Target process name
        $target = "MsMpEng.exe" wide ascii
        
        // Device name used by the vulnerable STProcessMonitor driver
        $device = "\\\\.\\STProcessMonitorDriver" wide ascii
        
        // IOCTL code: 0xB822200C (Little-endian: 0C 20 22 B8)
        $ioctl_code = { 0C 20 22 B8 }

        // Process enumeration strings often used in conjunction
        $api1 = "CreateToolhelp32Snapshot"
        $api2 = "Process32FirstW"
        $api3 = "Process32NextW"
        $api4 = "DeviceIoControl"

    condition:
        uint16(0) == 0x5A4D and (
            // Match the specific IOCTL and the Device path
            ($ioctl_code and $device) or
            
            // Or match the device path and the intent to kill Defender
            ($device and $target) or

            // Or look for the combination of the IOCTL and process enumeration
            ($ioctl_code and $target and 2 of ($api*))
        )
}
