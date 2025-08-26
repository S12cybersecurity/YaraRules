import "pe"

rule ETW_Event_Spoofing_Suspect
{
    meta:
        description = "Detects binaries likely abusing ETW by enumerating providers and spoofing events"
        author      = "0x12 Dark Development"
        date        = "2025-08-26"
        reference   = "ETW provider masquerading / event spoofing"

    strings:
        $s_enum      = "TdhEnumerateProviders" ascii wide nocase
        $s_reg       = "EventRegister" ascii wide
        $s_write     = "EventWrite" ascii wide
        $s_unreg     = "EventUnregister" ascii wide
        $s_desc      = "EVENT_DATA_DESCRIPTOR" ascii wide
        $s_provinfo  = "PROVIDER_ENUMERATION_INFO" ascii wide
        $s_tracearr  = "TraceProviderInfoArray" ascii wide
        $s_keywords1 = "defender" ascii wide nocase
        $s_keywords2 = "sysmon" ascii wide nocase
        $s_keywords3 = "antivirus" ascii wide nocase
        $s_keywords4 = "security" ascii wide nocase
        $s_keywords5 = "endpoint" ascii wide nocase

    condition:
        filesize < 50MB
        and pe.is_32bit() or pe.is_64bit()
        and pe.imports("tdh.dll", "TdhEnumerateProviders")
        and pe.imports("advapi32.dll", "EventRegister")
        and pe.imports("advapi32.dll", "EventWrite")
        and 2 of ($s_desc, $s_provinfo, $s_tracearr)
        and 1 of ($s_keywords1, $s_keywords2, $s_keywords3, $s_keywords4, $s_keywords5)
}
