rule BYOVD_KernelRW_PPL_Bypass_Generic
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects potential BYOVD usage with kernel R/W primitives targeting PPL bypass"
        date = "2026-03-18"
        reference = "Generic detection for vulnerable driver abuse and PPL tampering"

    strings:
        // Native API usage for driver/module enumeration
        $ntquery = "NtQuerySystemInformation" ascii wide
        $sysinfo_class = "SystemModuleInformation" ascii wide

        // Kernel / driver related indicators
        $ntdll = "ntdll.dll" ascii wide
        $device = "\\\\.\\ " ascii wide nocase
        $ioctl = "DeviceIoControl" ascii wide

        // Common kernel structures / targets
        $eprocess = "EPROCESS" ascii wide nocase
        $protection = "Protection" ascii wide nocase
        $siglevel = "SignatureLevel" ascii wide nocase

        // Privilege escalation / debugging
        $sedebug = "SeDebugPrivilege" ascii wide

        // Typical kernel primitives naming (generic, not exact)
        $read = "ReadPrimitive" ascii wide nocase
        $write = "WritePrimitive" ascii wide nocase

        // Kernel base / ntoskrnl hunting
        $ntos = "ntoskrnl.exe" ascii wide nocase
        $psinit = "PsInitialSystemProcess" ascii wide
        $psloaded = "PsLoadedModuleList" ascii wide

    condition:
        // Require a combination of behaviors, not just one indicator
        (
            $ntquery and $sysinfo_class and
            2 of ($ntos, $psinit, $psloaded)
        )
        and
        (
            $ioctl or $device
        )
        and
        (
            2 of ($eprocess, $protection, $siglevel)
        )
        and
        (
            $write or $read
        )
}
