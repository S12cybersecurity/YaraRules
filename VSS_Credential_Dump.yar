rule VSS_Credential_Dump
{
    meta:
        description = "Detects binaries using VSS API to access credential hive files"
        author      = "0x12 Dark Development"
        reference   = "T1003.002, T1003.003, T1003.004"

    strings:
        $vss_init    = "CreateVssBackupComponents" ascii wide
        $vss_snap    = "DoSnapshotSet" ascii wide
        $vss_prop    = "GetSnapshotProperties" ascii wide
        $sam         = "config\\SAM" ascii wide nocase
        $system      = "config\\SYSTEM" ascii wide nocase
        $security    = "config\\SECURITY" ascii wide nocase
        $shadow_dev  = "HarddiskVolumeShadowCopy" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        $vss_init and
        $vss_snap and
        (
            ($sam and $system) or
            $shadow_dev
        )
}
