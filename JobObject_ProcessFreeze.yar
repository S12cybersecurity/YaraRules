rule JobObject_ProcessFreeze
{
    meta:
        author      = "0x12 Dark Development"
        description = "Detects process freeze via undocumented JobObjectFreezeInformation (class 18)"
        reference   = "https://0x12darkdev.net"

    strings:
        $api1 = "CreateJobObject" ascii wide
        $api2 = "AssignProcessToJobObject" ascii wide
        $api3 = "SetInformationJobObject" ascii wide

        // JOBOBJECT_FREEZE_INFORMATION struct init: Flags union set to 1 (FreezeOperation bit)
        $struct_init = { C7 44 24 ?? 01 00 00 00 }

        // Freeze = TRUE pattern after zeroed struct
        $freeze_true  = { C6 44 24 ?? 01 }

        // Freeze = FALSE (unfreeze path)
        $freeze_false = { C6 44 24 ?? 00 }

    condition:
        uint16(0) == 0x5A4D and
        all of ($api*) and
        ($struct_init and ($freeze_true or $freeze_false))
}
