rule Thread_NameCalling_Shellcode_Copy_Technique {
    meta:
        description = "Detects the 'Thread Name-Calling' technique used only to copy shellcode into a remote process (without execution). Looks for SetThreadDescription + special APC to force GetThreadDescription memory allocation."
        author = "0x12 Dark Development"
        date = "2025-12-29"
        reference = "https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/"
        reference2 = "https://github.com/hasherezade/thread_namecalling"
        tlp = "WHITE"
        category = "memory_allocation"
        technique = "shellcode_copy_via_thread_description"

    strings:
        // Key API strings - most implementations import or resolve these
        $api_set = "SetThreadDescription" wide ascii
        $api_get = "GetThreadDescription" wide ascii
        $api_apc = "NtQueueApcThreadEx2" ascii
        $api_apc2 = "QueueUserAPC2" ascii  // documented wrapper

        // Special flag that forces GetThreadDescription to run and allocate memory
        $special_flag = { 04 00 00 00 }  // QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC = 4 (dword little-endian)

        // Common offset used to store the returned pointer (not required but very typical)
        $peb_340 = { 40 03 00 00 }  // 0x340 added to PEB base

        // Pattern often seen: payload ending with double NULL (required for SetThreadDescription)
        $double_null = { 00 00 00 00 }  // at least two wide NULLs

    condition:
        // Must have imports from where the thread description functions live
        (pe.imports("kernelbase.dll") or pe.imports("kernel32.dll"))

        and

        (
            // Main pattern: setting description + forcing GetThreadDescription via special APC
            $api_set and ($api_apc or $api_apc2) and $special_flag

            or

            // Alternative: both description APIs + special flag (even if APC name is resolved dynamically)
            (2 of ($api_set, $api_get)) and $special_flag

            or

            // Minimal but strong: SetThreadDescription + special APC flag (GetThreadDescription often resolved at runtime)
            $api_set and $special_flag
        )

        and

        // Bonus indicators - not required but increase confidence
        any of ($peb_340, $double_null)
}
