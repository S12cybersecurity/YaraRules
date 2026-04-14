rule SUSP_Worker_Factory_Injection_PoolParty {
    meta:
        author = "0x12 Dark Development"
        description = "Detects executables potentially utilizing the Worker Factory Start Routine Injection technique (PoolParty variant). Looks for handle enumeration, TpWorkerFactory targeting, and specific NtWorkerFactory APIs."
        date = "2026-04-14"
        version = "1.0"
        reference = "https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/"
        category = "Process Injection"

    strings:
        // Core Object Type String
        $obj = "TpWorkerFactory" ascii wide nocase

        // Critical NT APIs for Worker Factory Manipulation
        // These are highly specific to this technique.
        $nt1 = "NtQueryInformationWorkerFactory" ascii wide
        $nt2 = "NtSetInformationWorkerFactory" ascii wide

        // Handle Enumeration & Duplication APIs
        $enum1 = "NtQuerySystemInformation" ascii wide
        $enum2 = "NtQueryObject" ascii wide
        $dup1 = "DuplicateHandle" ascii wide
        $dup2 = "NtDuplicateObject" ascii wide

        // Memory Manipulation APIs (Standard Win32 and NT)
        $mem1 = "VirtualProtectEx" ascii wide
        $mem2 = "NtProtectVirtualMemory" ascii wide
        $mem3 = "WriteProcessMemory" ascii wide
        $mem4 = "NtWriteVirtualMemory" ascii wide

    condition:
        // Must be a PE file (Windows Executable)
        uint16(0) == 0x5a4d and
        
        // Keep performance in check by limiting file size
        filesize < 10MB and
        
        // Must contain the target object type string
        $obj and
        
        // Must reference the core Worker Factory modification APIs
        all of ($nt*) and
        
        // Must reference at least two APIs related to finding/hijacking the handle
        2 of ($enum1, $enum2, $dup1, $dup2) and
        
        // Must reference at least one cross-process memory manipulation API
        1 of ($mem*)
}
