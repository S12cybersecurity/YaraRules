rule Persistence_StartupDirectory
{
    meta:
        author      = "0x12 Dark Development"
        description = "Detects executables that attempt to achieve persistence by dropping or referencing the Windows Startup directory"
        reference   = "https://attack.mitre.org/techniques/T1547/001/"
        category    = "persistence"
        severity    = "high"
        date        = "2025-03-25"

    strings:
        // --- Startup folder path fragments (Unicode + ASCII) ---
        $path_startup_u   = "\\Start Menu\\Programs\\Startup" wide nocase
        $path_startup_a   = "\\Start Menu\\Programs\\Startup" ascii nocase
        $path_programdata = "\\ProgramData\\Microsoft\\Windows\\Start Menu" wide ascii nocase
        $path_appdata     = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu" wide ascii nocase

        // --- Environment variable references ---
        $env_appdata      = "%APPDATA%" wide ascii nocase
        $env_programdata  = "%PROGRAMDATA%" wide ascii nocase
        $env_userprofile  = "%USERPROFILE%" wide ascii nocase

        // --- Shell API used to resolve Startup folder ---
        $api_shgetfolder  = "SHGetFolderPathW" ascii
        $api_shgetknown   = "SHGetKnownFolderPath" ascii

        // --- CSIDL / FOLDERID constants (often appear as byte patterns in imports/data) ---
        // CSIDL_STARTUP = 0x07, CSIDL_COMMON_STARTUP = 0x18
        // FOLDERID_Startup string reference
        $folderid_startup = "FOLDERID_Startup" wide ascii nocase
        $folderid_cstartup = "FOLDERID_CommonStartup" wide ascii nocase

        // --- File drop APIs ---
        $api_copyfile     = "CopyFileW" ascii
        $api_copyfileex   = "CopyFileExW" ascii
        $api_movefile     = "MoveFileW" ascii
        $api_createfile   = "CreateFileW" ascii
        $api_writefile    = "WriteFile" ascii

        // --- LNK shortcut creation (COM-based) ---
        $com_shelllink    = "IShellLinkW" ascii nocase
        $com_persist      = "IPersistFile" ascii nocase
        $clsid_shelllink  = "{00021401-0000-0000-C000-000000000046}" ascii nocase

        // --- PowerShell / scripting variants ---
        $ps_startup       = "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase
        $ps_startup2      = "shell:startup" nocase
        $ps_wscript       = "WScript.Shell" nocase
        $ps_specialfolder = "SpecialFolders" nocase

        // --- Registry-based startup path resolution (alternative) ---
        $reg_startup_key  = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" wide ascii nocase

    condition:
        uint16(0) == 0x5A4D  // MZ header (PE file)
        and filesize < 10MB
        and (
            // Direct path reference + file operation
            (
                (1 of ($path_startup_u, $path_startup_a, $path_programdata, $path_appdata))
                and (1 of ($api_copyfile, $api_copyfileex, $api_movefile, $api_writefile, $api_createfile))
            )
            or
            // Shell API resolution + file drop
            (
                (1 of ($api_shgetfolder, $api_shgetknown))
                and (1 of ($api_copyfile, $api_copyfileex, $api_movefile, $api_writefile))
            )
            or
            // FOLDERID constant reference + file operation
            (
                (1 of ($folderid_startup, $folderid_cstartup))
                and (1 of ($api_copyfile, $api_copyfileex, $api_movefile, $api_writefile, $api_createfile))
            )
            or
            // COM-based LNK shortcut creation targeting Startup
            (
                (1 of ($com_shelllink, $com_persist, $clsid_shelllink))
                and (1 of ($path_startup_u, $path_startup_a, $path_programdata, $path_appdata))
            )
            or
            // Scripting / PowerShell variants
            (2 of ($ps_startup, $ps_startup2, $ps_wscript, $ps_specialfolder, $env_appdata, $env_programdata))
            or
            // Registry-based path resolution + file op
            (
                $reg_startup_key
                and (1 of ($api_copyfile, $api_movefile, $api_writefile, $api_createfile))
            )
        )
}
