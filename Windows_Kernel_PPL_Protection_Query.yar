rule Windows_Kernel_PPL_Protection_Query
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects kernel drivers that query Protected Process Light (PPL) protection levels via IOCTL"
        date = "2026-01-28"
        version = "1.0"
        severity = "medium"
        category = "offensive-security"
        technique = "Process Protection Enumeration"
        
    strings:
        // PS_PROTECTION structure patterns
        $ps_protection_struct1 = "PS_PROTECTION" ascii wide
        $ps_protection_struct2 = "_PS_PROTECTION" ascii wide
        
        // Critical kernel API functions for process lookup
        $kernel_api1 = "PsLookupProcessByProcessId" ascii wide
        $kernel_api2 = "IoCreateDevice" ascii wide
        $kernel_api3 = "IoCreateSymbolicLink" ascii wide
        $kernel_api4 = "IoCompleteRequest" ascii wide
        
        // EPROCESS structure reference
        $eprocess1 = "EPROCESS" ascii wide
        $eprocess2 = "_EPROCESS" ascii wide
        $eprocess3 = "PEPROCESS" ascii wide
        
        // IOCTL patterns - common device control codes
        $ioctl_pattern1 = "IRP_MJ_DEVICE_CONTROL" ascii wide
        $ioctl_pattern2 = "DeviceIoControl" ascii wide
        $ioctl_pattern3 = { 49 52 50 5F 4D 4A 5F 44 45 56 49 43 45 5F 43 4F 4E 54 52 4F 4C } // "IRP_MJ_DEVICE_CONTROL"
        
        // CTL_CODE macro patterns (typical IOCTL construction)
        $ctl_code = "CTL_CODE" ascii wide
        
        // Device/DosDevices naming patterns
        $device_path1 = "\\Device\\" ascii wide
        $device_path2 = "\\DosDevices\\" ascii wide
        $device_path3 = { 5C 00 44 00 65 00 76 00 69 00 63 00 65 00 5C 00 } // "\Device\" wide
        $device_path4 = { 5C 00 44 00 6F 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5C 00 } // "\DosDevices\" wide
        
        // Protection level field references
        $protection_field1 = ".Protection" ascii wide
        $protection_field2 = "Protection :" ascii wide
        $protection_field3 = "protectionLevel" ascii wide
        
        // Bit manipulation patterns for Type/Signer/Audit extraction
        $bitmask1 = { 83 E0 07 } // AND EAX, 0x7 (Type extraction)
        $bitmask2 = { 83 E0 0F } // AND EAX, 0xF (Signer extraction)
        $bitmask3 = { C1 E? 03 } // SHR/SHL by 3 (Audit bit shift)
        $bitmask4 = { C1 E? 04 } // SHR/SHL by 4 (Signer shift)
        
        // IRP handling patterns
        $irp_pattern1 = "PIRP" ascii wide
        $irp_pattern2 = "IoGetCurrentIrpStackLocation" ascii wide
        $irp_pattern3 = "AssociatedIrp.SystemBuffer" ascii wide
        
        // Driver entry and unload patterns
        $driver_entry = "DriverEntry" ascii wide
        $driver_unload = "DriverUnload" ascii wide
        
        // PID/Process ID handling
        $pid_handling1 = "ProcessId" ascii wide
        $pid_handling2 = "ULONG_PTR)ProcessId" ascii wide
        
        // Protection type/signer constants or strings
        $signer_str1 = "WinTcb" ascii wide nocase
        $signer_str2 = "Antimalware" ascii wide nocase
        $signer_str3 = "Authenticode" ascii wide nocase
        $signer_str4 = "CodeGen" ascii wide nocase
        
    condition:
        uint16(0) == 0x5A4D and // PE file
        (
            // Strong kernel driver indicators
            (
                $driver_entry and 
                $kernel_api2 and 
                $kernel_api3
            )
            or
            // Driver exports
            pe.exports("DriverEntry")
        )
        and
        (
            // PS_PROTECTION structure usage
            any of ($ps_protection_struct*)
            or
            // EPROCESS manipulation
            (
                any of ($eprocess*) and
                $kernel_api1
            )
        )
        and
        (
            // IOCTL communication mechanism
            (
                any of ($ioctl_pattern*) and
                ($ctl_code or any of ($irp_pattern*))
            )
            or
            // Device creation with symbolic link
            (
                $kernel_api2 and
                $kernel_api3 and
                any of ($device_path*)
            )
        )
        and
        (
            // Protection field access or bit manipulation
            any of ($protection_field*) or
            2 of ($bitmask*)
        )
        and
        // File size reasonable for kernel driver
        filesize < 500KB
}
