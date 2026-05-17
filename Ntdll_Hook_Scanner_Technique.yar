rule Ntdll_Hook_Scanner_Technique
{
    meta:
        description = "Detects tools that scan ntdll.dll exports by comparing in-memory bytes against the on-disk PE to identify inline hooks placed by EDR/AV products"
        author      = "0x12 Dark Development"
        date        = "2026-05-17"
        technique   = "T1562.001 - Impair Defenses: Disable or Modify Tools"
        severity    = "high"
        category    = "defense_evasion"

    strings:
        // PE export table structures accessed by name
        $str_ntdll          = "ntdll.dll"              ascii wide
        $str_system32       = "System32"               ascii wide nocase
        $str_system32_2     = "system32\\ntdll.dll"    ascii wide nocase

        // Export directory field names or string references in debug builds
        $str_export_dir     = "IMAGE_EXPORT_DIRECTORY" ascii wide
        $str_addr_names     = "AddressOfNames"         ascii wide
        $str_addr_funcs     = "AddressOfFunctions"     ascii wide

        // Hook signature byte patterns searched in memory
        // JMP rel32 first byte — 0xE9
        $hook_sig_e9        = { E9 ?? ?? ?? ?? }
        // JMP [RIP+offset] — 0xFF 0x25
        $hook_sig_ff25      = { FF 25 ?? ?? ?? ?? }
        // MOV RAX trampoline — 0x48 0xB8
        $hook_sig_48b8      = { 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0 }

        // GetModuleHandleA("ntdll.dll") pattern — common in hook scanners
        $api_getmodule      = "GetModuleHandleA"       ascii wide
        $api_getconsole     = "GetConsoleMode"         ascii wide

        // Section characteristic flag IMAGE_SCN_MEM_EXECUTE = 0x20000000
        $scn_exec_flag      = { 00 00 00 20 }

        // memcmp used to compare memory vs disk bytes
        $api_memcmp         = "memcmp"                 ascii wide

        // ifstream binary open of a PE file from disk
        $str_binary_flag    = "binary"                 ascii wide
        $str_ios_ate        = { 08 00 00 00 }          // std::ios::ate value

    condition:
        uint16(0) == 0x5A4D and     // MZ header
        filesize < 3MB and

        // Must reference ntdll and System32 — loading disk copy
        $str_ntdll and
        ($str_system32 or $str_system32_2) and

        // Must use GetModuleHandleA to get in-memory base
        $api_getmodule and

        // Must contain at least two hook byte signatures being searched
        2 of ($hook_sig_e9, $hook_sig_ff25, $hook_sig_48b8) and

        // Must use memcmp — the core comparison primitive
        $api_memcmp and

        // Must reference the executable section flag or export table fields
        (
            $scn_exec_flag or
            any of ($str_export_dir, $str_addr_names, $str_addr_funcs)
        )
}
