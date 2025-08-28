rule ETW_Abuse_Technique
{
    meta:
        description = "Detects binaries abusing ETW providers via EventRegister/EventWrite techniques"
        author = "0x12 Dark Development"
        date = "2025-08-28"
        reference = "ETW abuse / evasion research"

    strings:
        $s1 = "EventRegister" ascii wide
        $s2 = "EventUnregister" ascii wide
        $s3 = "EventWrite" ascii wide
        $s4 = "StartTrace" ascii wide
        $s5 = "StopTrace" ascii wide
        $s6 = "EnableTraceEx2" ascii wide
        $s7 = "OpenTrace" ascii wide
        $s8 = "ProcessTrace" ascii wide
        $lib1 = "tdh.dll" ascii wide
        $lib2 = "advapi32.dll" ascii wide

    condition:
        (1 of ($s1,$s2,$s3)) and
        (1 of ($s4,$s5,$s6,$s7,$s8)) and
        (any of ($lib1,$lib2))
}
