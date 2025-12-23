rule CMSTP_UAC_Bypass_General {
    meta:
        author = "0x12 Dark Development"
        description = "Detects generic indicators of CMSTP UAC bypass technique in binaries or scripts. Looks for common strings used in implementations that create malicious .inf files and abuse cmstp.exe."
        date = "2025-12-23"
        reference = "MITRE ATT&CK T1548.002 and T1218.003 - Abuse Elevation Control Mechanism / System Binary Proxy Execution: CMSTP"
        technique = "CMSTP.exe with malicious .inf containing RunPreSetupCommands"
        score = 70

    strings:
        // Common path to cmstp.exe
        $path1 = "cmstp.exe" ascii wide nocase
        $path2 = "system32\\cmstp.exe" ascii wide nocase

        // Common arguments
        $arg1 = "/au" ascii wide
        $arg2 = "/s" ascii wide
        $arg3 = "/ni" ascii wide
        $arg4 = "-au" ascii wide
        $arg5 = "-s" ascii wide

        // Typical .inf content sections and keys
        $inf1 = "RunPreSetupCommands" ascii wide
        $inf2 = "[DefaultInstall]" ascii wide
        $inf3 = "Signature=$chicago$" ascii wide
        $inf4 = "CustInstDestSection" ascii wide
        $inf5 = "AllUSer_LDIDSection" ascii wide

        // Common window title used for auto-accept
        $win1 = "CorpVPN" ascii wide

        // Common Windows API calls in implementations
        $api1 = "ShellExecute" ascii wide
        $api2 = "FindWindow" ascii wide
        $api3 = "PostMessage" ascii wide
        $api4 = "VK_RETURN" ascii wide

        // Temp path often used
        $temp = "C:\\windows\\temp\\" ascii wide

    condition:
        uint16(0) == 0x5A4D  // PE executable (MZ header) - to avoid matching plain .inf files
        and $path1
        and (any of ($arg*) or any of ($inf*) or $win1)
        and (any of ($api*) or $temp)
}
