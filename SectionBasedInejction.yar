import "pe"

rule DarkDev_SectionBasedInjection
{
    meta:
        author = "0x12 Dark Development"
        description = "Detect binaries that reference APIs/constants commonly used for section-based process injection (NtCreateSection / NtMapViewOfSection / RtlCreateUserThread / CreateRemoteThread). Defensive detection only."
        date = "2025-11-10"
        version = "1.0"
        license = "proprietary"
        reference = "defensive/detection"

    strings:
        /* ntdll / kernel32 APIs commonly seen in section-based injection */
        $ntCreateSection         = "NtCreateSection" ascii wide
        $zwCreateSection         = "ZwCreateSection" ascii wide
        $ntMapViewOfSection      = "NtMapViewOfSection" ascii wide
        $zwMapViewOfSection      = "ZwMapViewOfSection" ascii wide
        $rtlCreateUserThread     = "RtlCreateUserThread" ascii wide
        $ntCreateThreadEx        = "NtCreateThreadEx" ascii wide
        $zwCreateThread          = "ZwCreateThread" ascii wide
        $createRemoteThread      = "CreateRemoteThread" ascii wide
        $openProcess             = "OpenProcess" ascii wide

        /* memory protection / section related constants (ascii only for broader hit-rate) */
        $PAGE_EXECUTE_READWRITE  = "PAGE_EXECUTE_READWRITE" ascii
        $PAGE_EXECUTE_READ       = "PAGE_EXECUTE_READ" ascii
        $SECTION_MAP_READ        = "SECTION_MAP_READ" ascii
        $SECTION_MAP_WRITE       = "SECTION_MAP_WRITE" ascii
        $SECTION_MAP_EXECUTE     = "SECTION_MAP_EXECUTE" ascii
        $SEC_COMMIT              = "SEC_COMMIT" ascii

        /* fallbacks / IPC alternatives that sometimes appear in benign code */
        $CreateFileMapping       = "CreateFileMapping" ascii wide
        $MapViewOfFile           = "MapViewOfFile" ascii wide

    condition:
        pe.is_pe and
        (
            /* require presence of at least one API/string from the ntdll/kernel32 set */
            1 of ($ntCreateSection, $zwCreateSection, $ntMapViewOfSection, $zwMapViewOfSection,
                  $rtlCreateUserThread, $ntCreateThreadEx, $zwCreateThread, $createRemoteThread, $openProcess)
        ) and
        (
            /* either (A) clear sequence of section + map + remote-thread APIs, or (B) multiple suspicious memory/section constants */
            (
                1 of ($ntCreateSection, $zwCreateSection) and
                1 of ($ntMapViewOfSection, $zwMapViewOfSection, $MapViewOfFile) and
                1 of ($rtlCreateUserThread, $ntCreateThreadEx, $zwCreateThread, $createRemoteThread)
            )
            or
            (
                2 of ($PAGE_EXECUTE_READWRITE, $PAGE_EXECUTE_READ, $SECTION_MAP_READ, $SECTION_MAP_WRITE, $SECTION_MAP_EXECUTE, $SEC_COMMIT)
            )
        ) and
        /* Prefer binaries that import from ntdll/kernel32 (helps reduce noise). Adjust or remove if scanning memory or non-PE blobs. */
        ( pe.imports("ntdll.dll") or pe.imports("kernel32.dll") )
}
