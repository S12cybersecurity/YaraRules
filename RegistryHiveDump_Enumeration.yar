rule RegistryHiveDump_Enumeration
{
    meta:
        author      = "0x12 Dark Development"
        description = "Detects binaries that dynamically resolve NtSaveKeyEx or related APIs to dump Windows registry hives. Commonly used in post-exploitation for credential access and offline registry enumeration."
        reference   = "https://medium.com/@s12deff"
        mitre       = "T1003.002 - OS Credential Dumping: Security Account Manager"
        date        = "2025-07-14"

    strings:
        // Core technique — NtSaveKeyEx must appear as a string because
        // it is resolved dynamically via GetProcAddress at runtime
        $ntsavekeyex     = "NtSaveKeyEx"  ascii wide

        // Fallback save APIs that can be abused the same way
        $regsavekeyex    = "RegSaveKeyEx" ascii wide
        $regsavekey      = "RegSaveKey"   ascii wide

        // SeBackupPrivilege is required to read SAM and SECURITY hives
        $backup_priv1    = "SeBackupPrivilege" ascii wide
        $backup_priv2    = "SE_BACKUP_NAME"    ascii wide

        // Native loader used to resolve the undocumented API manually
        $ntdll           = "ntdll.dll" ascii wide nocase

        // Token privilege manipulation required before the dump
        $adj_token       = "AdjustTokenPrivileges" ascii

        // Common high-value hive targets
        $hive_sam        = "SAM"      ascii wide
        $hive_security   = "SECURITY" ascii wide
        $hive_system     = "SYSTEM"   ascii wide
        $hive_software   = "SOFTWARE" ascii wide

        // Output file extensions for exported hive files
        $ext_hiv         = ".hiv"  ascii wide nocase
        $ext_hive        = ".hive" ascii wide nocase

    condition:
        // Must be a PE file
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            // Scenario A: undocumented NtSaveKeyEx path
            // String present for GetProcAddress + ntdll + privilege setup
            (
                $ntsavekeyex and
                $ntdll and
                ( $backup_priv1 or $backup_priv2 )
            )
            or
            // Scenario B: documented API path with deliberate privilege abuse
            // RegSaveKey/RegSaveKeyEx + AdjustTokenPrivileges + targeting protected hives
            (
                ( $regsavekeyex or $regsavekey ) and
                $adj_token and
                ( $backup_priv1 or $backup_priv2 ) and
                2 of ( $hive_sam, $hive_security, $hive_system, $hive_software )
            )
        ) and
        // At least one hive output indicator or two targeted hive names
        (
            ( $ext_hiv or $ext_hive ) or
            2 of ( $hive_sam, $hive_security, $hive_system, $hive_software )
        )
}
