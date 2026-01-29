rule Win_ProcessInjection_QueueUserAPC2_Special {
    meta:
        description = "Detects potential remote process injection using QueueUserAPC2 with Special User APC flags"
        author = "0x12 Dark Development"
        technique = "APC Injection"
        threat_level = "High"

    strings:
        // Core APIs for thread/process enumeration
        $api1 = "CreateToolhelp32Snapshot" ascii wide
        $api2 = "Thread32First" ascii wide
        $api3 = "Thread32Next" ascii wide
        
        // The injection/execution functions
        $apc1 = "QueueUserAPC2" ascii wide
        $apc2 = "NtTestAlert" ascii wide
        $apc3 = "QueueUserAPC" ascii wide

        // The specific flag for Special User APCs (QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC = 0x00000001)
        // We look for the hex representation or common surrounding code patterns
        $flag_hex = { 01 00 00 00 } 

    condition:
        uint16(0) == 0x5A4D and // Check for PE header
        (
            // Logic: Must have enumeration capability + the specific APC call
            (2 of ($api*)) and 
            ($apc1 or ($apc2 and $apc3)) and
            $flag_hex
        )
}
