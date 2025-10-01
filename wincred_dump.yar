rule 0x12_DarkDev_WinCred_Dump_Technique
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects binaries that use Windows Credential Manager APIs and related data-protection APIs — intended to flag the credential-dump technique, not a specific sample."
        date = "2025-10-01"
        license = "proprietary"
        reference = "Detects imports/strings commonly used when enumerating or extracting Windows Credential Manager/Vault entries"
        severity = "medium"

    strings:
        // API names commonly used to enumerate/read/free credentials
        $s_cred_enum_w = "CredEnumerateW" ascii wide
        $s_cred_read_w = "CredReadW" ascii wide
        $s_cred_free   = "CredFree" ascii wide
        $s_cred_write  = "CredWriteW" ascii wide
        $s_cred_delete = "CredDeleteW" ascii wide

        // Data Protection APIs often used to decrypt DPAPI-protected blobs
        $s_dpapi1 = "CryptUnprotectData" ascii wide
        $s_dpapi2 = "CryptProtectData" ascii wide

        // Console/output strings and vault-related literal tokens that dumping tools often include
        $s_targetname = "TargetName" ascii wide
        $s_credentialblob = "CredentialBlob" ascii wide
        $s_credential = "Credential" ascii wide
        $s_vault = "Vault" ascii wide
        $s_credmgr = "Credential Manager" ascii wide
        $s_credmgr2 = "CredentialManager" ascii wide

        // Generic suspicious combinations: presence of Cred* + CryptUnprotectData
        $s_printf = "printf(" ascii
        $s_wprintf = "wprintf" ascii wide

    condition:
        // Only apply to PE files
        uint16(0) == 0x5A4D and

        // Heuristic: at least one credential API import AND one of (DPAPI or vault/credential related strings)
        (
            (
                any of ($s_cred_enum_w, $s_cred_read_w, $s_cred_free, $s_cred_write, $s_cred_delete)
            )
            and
            (
                any of ($s_dpapi1, $s_dpapi2) or any of ($s_targetname, $s_credentialblob, $s_vault, $s_credmgr, $s_credential)
            )
        )

        // Avoid trivial false positives: require file size > 2KB
        and filesize > 2048
}
