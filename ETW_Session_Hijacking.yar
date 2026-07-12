rule ETW_Session_Hijacking
{
    meta:
        author      = "0x12 Dark Development"
        description = "Detects binaries that enumerate ETW sessions and redirect log output"
        reference   = "https://0x12darkdev.net"
        severity    = "high"

    strings:
        // Core ETW management imports
        $imp1 = "QueryAllTraces"    ascii wide
        $imp2 = "StopTrace"        ascii wide
        $imp3 = "StartTrace"       ascii wide
        $imp4 = "QueryTrace"       ascii wide

        // Suspicious log redirection targets
        $path1 = "\\Temp\\"       ascii wide nocase
        $path2 = "hijacked.etl"   ascii wide nocase
        $path3 = "\\AppData\\"    ascii wide nocase

        // Struct field keyword pattern
        $field1 = "LogFileNameOffset"  ascii wide
        $field2 = "LoggerNameOffset"   ascii wide

        // advapi32 import (ETW management lives here)
        $lib = "advapi32.dll" ascii nocase

    condition:
        uint16(0) == 0x5A4D and          // MZ header
        $lib and
        (
            // Must use stop + start trace pair
            ($imp2 and $imp3) or
            // Or enumerate all + stop
            ($imp1 and $imp2)
        ) and
        // Plus a suspicious output path
        any of ($path*)
}
