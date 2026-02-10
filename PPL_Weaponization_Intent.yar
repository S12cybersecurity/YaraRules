rule PPL_Weaponization_Intent {
    meta:
        description = "Detects binaries attempting to escalate to PPL (Protected Process Light) via Driver IOCTL"
        author = "0x12 Dark Development"
        technique = "Process Immortality / DKOM"
        date = "2024-05-22"

    strings:
        // PPL Logic: Looking for the bitmask values
        // Signer 3 (Antimalware), Type 1 (ProtectedLight)
        $ppl_signer_antimalware = { C6 ?? ?? 03 } // Possible assignment of Signer level
        $ppl_type_light = { C6 ?? ?? 01 }        // Possible assignment of Protection type

        // IOCTL and Driver Strings
        $ioctl_code = { 00 08 00 00 22 } // 0x800 IOCTL or similar custom ranges
        $dev_path = "\\\\.\\" wide ascii   // Driver communication prefix
        
        // Characteristic API calls
        $api1 = "DeviceIoControl"
        $api2 = "GetCurrentProcessId"
        $api3 = "CreateFileA"

    condition:
        uint16(0) == 0x5A4D and // MZ Header
        all of ($api*) and
        $dev_path and
        (any of ($ppl_*))
}
