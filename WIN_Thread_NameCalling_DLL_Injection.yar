rule WIN_Thread_NameCalling_DLL_Injection_0x12DarkDev
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects binaries implementing the DLL injection variant of the 'Thread Name-Calling' technique. Abuses SetThreadDescription/GetThreadDescription to copy a DLL path into remote process memory (via PEB+0x340 side-effect), then queues an APC to invoke LoadLibraryW/A on that remote path. Designed to catch custom implementations and malware using this specific DLL-loading method."
        date = "2025-12-30"
        version = "1.1"
        mitre = "T1055.001" // Process Injection - Dynamic-link Library Injection
        confidence = "High"
        category = "Process Injection - DLL Injection"
        reference = "https://github.com/hasherezade/thread_namecalling (dll_inj variant)"
        reference2 = "https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/"

    strings:
        // Core thread description APIs for data copy
        $thread_desc1 = "SetThreadDescription" ascii wide
        $thread_desc2 = "GetThreadDescription" ascii wide

        // APC queuing for remote LoadLibrary call
        $apc1 = "NtQueueApcThreadEx" ascii wide
        $apc2 = "NtQueueApcThreadEx2" ascii wide
        $apc3 = "QueueUserApc2" ascii wide

        // PEB retrieval to locate the unused field
        $peb_query = "NtQueryInformationProcess" ascii wide

        // Critical for DLL variant: remote LoadLibrary call
        $loadlib1 = "LoadLibraryW" ascii wide
        $loadlib2 = "LoadLibraryA" ascii wide

        // Indicator of PEB+0x340 usage (binary dword or string forms)
        $offset_bin = { 40 03 00 00 }                     // 0x340 little-endian
        $offset_str1 = "0x340" ascii wide
        $offset_str2 = "340h" ascii wide

    condition:
        // PE file
        uint16(0) == 0x5A4D and

        // Must have the thread description pair
        ($thread_desc1 and $thread_desc2) and

        // Must have LoadLibrary (specific to DLL variant)
        any of ($loadlib1, $loadlib2) and

        // Must have APC queuing
        any of ($apc1, $apc2, $apc3) and

        // Must query PEB
        $peb_query and

        // Strongly prefer presence of 0x340 indicator (increases specificity)
        any of ($offset*)
}
