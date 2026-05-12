rule PDB_Symbol_Resolution_Kernel_Offsets
{
    meta:
        author      = "0x12 Dark Development"
        description = "Detects binaries attempting to resolve kernel structure offsets via PDB symbol server queries at runtime"
        reference   = "https://medium.com/@0x12"
        severity    = "high"
        category    = "offensive-toolkit"
        date        = "2026-05-12"

    strings:
        // Microsoft symbol server URLs and path patterns
        $sym_srv1   = "msdl.microsoft.com" ascii wide nocase
        $sym_srv2   = "symsrv.dll"         ascii wide nocase
        $sym_srv3   = "/download/symbols/" ascii wide nocase
        $sym_srv4   = "ntoskrnl.pdb"       ascii wide nocase

        // DbgHelp functions used to load and query PDB type info
        $dbg1       = "SymInitialize"        ascii
        $dbg2       = "SymLoadModuleEx"      ascii
        $dbg3       = "SymGetTypeFromName"   ascii
        $dbg4       = "SymGetTypeInfo"       ascii
        $dbg5       = "SymFromName"          ascii
        $dbg6       = "SymSetOptions"        ascii
        $dbg7       = "TI_GET_OFFSET"        ascii
        $dbg8       = "TI_FINDCHILDREN"      ascii

        // Kernel module enumeration via NtQuerySystemInformation
        $nt1        = "NtQuerySystemInformation" ascii
        $nt2        = "SystemModuleInformation"  ascii

        // Target kernel structures commonly resolved for offensive use
        $struct1    = "_EPROCESS"            ascii wide
        $struct2    = "_ETHREAD"             ascii wide
        $struct3    = "_KTHREAD"             ascii wide
        $struct4    = "_TOKEN"               ascii wide

        // High-value fields queried for privilege escalation / token manipulation
        $field1     = "Token"                ascii wide
        $field2     = "ActiveProcessLinks"   ascii wide
        $field3     = "UniqueProcessId"      ascii wide
        $field4     = "MitigationFlags"      ascii wide
        $field5     = "SignatureLevel"       ascii wide
        $field6     = "Protection"           ascii wide

        // WinInet / HTTP used to pull PDB from network
        $inet1      = "InternetOpenUrlA"     ascii
        $inet2      = "InternetReadFile"     ascii
        $inet3      = "InternetOpenA"        ascii
        $inet4      = "WinHttpOpen"          ascii
        $inet5      = "WinHttpSendRequest"   ascii

        // PE parsing indicators — Debug Directory access patterns
        $pe1        = "IMAGE_DEBUG_TYPE_CODEVIEW" ascii
        $pe2        = "RSDS"                      ascii
        $pe3_bytes  = { 52 53 44 53 }             // 'RSDS' raw bytes

        // ntoskrnl loaded path patterns
        $path1      = "ntoskrnl.exe"         ascii wide nocase
        $path2      = "\\SystemRoot\\"       ascii wide nocase
        $path3      = "System32\\ntos"       ascii wide nocase

    condition:
        uint16(0) == 0x5A4D               // valid PE
        and filesize < 20MB

        and (
            // Core: symbol server contact + DbgHelp usage
            (
                1 of ($sym_srv*)
                and 2 of ($dbg*)
            )
            or
            // Core: kernel module enumeration + PDB parsing
            (
                all of ($nt*)
                and 1 of ($dbg*)
                and 1 of ($path*)
            )
            or
            // Broader: HTTP download + DbgHelp + kernel struct names
            (
                1 of ($inet*)
                and 2 of ($dbg*)
                and 1 of ($struct*)
            )
        )

        // Raise confidence if sensitive kernel fields are also present
        and (
            1 of ($field*)
            or 1 of ($struct*)
        )
}
