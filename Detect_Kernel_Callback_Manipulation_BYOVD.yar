rule Detect_Kernel_Callback_Manipulation_BYOVD {
    meta:
        author = "0x12 Dark Development"
        description = "Detects tools that enumerate and overwrite Windows Kernel Process Creation Callbacks via BYOVD"
        technique = "Kernel Callback Blinding"
        category = "Post-Exploitation / Evasion"
        date = "2026-04-23"

    strings:
        // Kernel artifacts and routine names
        $kernel_name = "ntoskrnl.exe" nocase
        $routine = "PspCreateProcessNotifyRoutine"
        $priv = "SeDebugPrivilege"

        // Native API for driver enumeration
        $api1 = "NtQuerySystemInformation"
        $api2 = "SystemModuleInformation"

        // Bitwise operations for pointer decoding/encoding (Common in these tools)
        // Mask for decoding: value & ~0xF (or similar bits)
        $mask_decode = { 48 25 f? ff ff ff } 
        
        // Kernel pointer fixing (0xffff000000000000 | (val >> 16))
        $fix_pointer = { 48 b8 00 00 00 00 00 00 ff ff }
        
        // Pointer encoding (val << 16)
        $encode_ptr = { 48 c1 e? 10 }

        // Logic for interacting with drivers
        $ioctl = "DeviceIoControl"

    condition:
        // Check for MZ header
        uint16(0) == 0x5A4D and 
        (
            // Must have the routine name or the kernel name + privilege escalation
            ($routine) or ($kernel_name and $priv)
        ) 
        and 
        (
            // Must include enumeration logic and at least one pointer manipulation pattern
            $api1 and ($mask_decode or $fix_pointer or $encode_ptr) and $ioctl
        )
}
