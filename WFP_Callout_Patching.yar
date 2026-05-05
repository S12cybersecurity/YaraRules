rule WFP_Callout_Patching
{
    meta:
        author      = "0x12 Dark Development"
        description = "Detects WFP Callout Patching technique — usermode tooling that locates the NETIO!gWfpGlobal callout array and overwrites ClassifyFunction pointers with a CFG-valid stub to silence EDR network telemetry. Not tied to a specific implementation."
        severity    = "critical"
        category    = "defense-evasion"
        technique   = "WFP Callout ClassifyFunction Patching"

    strings:
        // netio.sys targeted to locate gWfpGlobal and FeDefaultClassifyCallback
        $netio_1 = "netio.sys"                      ascii wide nocase
        $netio_2 = "netio"                          ascii wide nocase

        // WFP management API used to enumerate registered callouts from usermode
        // without kernel access — standard technique to get CalloutIds
        $fwpm_1 = "FwpmCalloutEnum"                 ascii wide
        $fwpm_2 = "FwpmCalloutCreateEnumHandle"     ascii wide
        $fwpm_3 = "FwpmEngineOpen"                  ascii wide
        $fwpm_4 = "FwpmFreeMemory"                  ascii wide

        // WFP kernel-side exports referenced to locate or validate callout structures
        $fwps_1 = "FwpsCalloutRegister"             ascii wide
        $fwps_2 = "FwpsCalloutUnregisterById"       ascii wide

        // FeDefaultClassifyCallback — the CFG-valid replacement target
        // Appears as a string in debug builds or as a pattern scan target
        $fe_default_1 = "FeDefaultClassifyCallback" ascii wide
        $fe_default_2 = "FeGetWfpGlobalPtr"         ascii wide

        // gWfpGlobal — root structure of WFP internals, referenced in tooling strings
        $wfp_global = "gWfpGlobal"                  ascii wide

        // Vulnerable drivers commonly used for kernel R/W primitives (BYOVD)
        $byovd_1 = "RTCore64"                       ascii wide
        $byovd_2 = "\\.\GIO"                        ascii wide
        $byovd_3 = "dbutil_2_3"                     ascii wide
        $byovd_4 = "WinRing0"                       ascii wide
        $byovd_5 = "PROCEXP152"                     ascii wide

        // NtQuerySystemInformation used to enumerate kernel modules
        // and find netio.sys base address
        $nt_sysmod = "NtQuerySystemInformation"     ascii wide

        // DeviceIoControl — used to communicate with the vulnerable driver
        $devioctl = "DeviceIoControl"               ascii wide

        // ALE Auth Connect layer GUIDs — the standard EDR network monitoring layer
        // FWPM_LAYER_ALE_AUTH_CONNECT_V4: {c38d57d1-05a7-4c33-904f-7fbceee60e82}
        $ale_v4_guid = { D1 57 8D C3 A7 05 33 4C 90 4F 7F BC EE E6 0E 82 }
        // FWPM_LAYER_ALE_AUTH_CONNECT_V6: {4a72393b-319f-44bc-84c3-ba54dcb3b6b4}
        $ale_v6_guid = { 3B 39 72 4A 9F 31 BC 44 84 C3 BA 54 DC B3 B6 B4 }

        // Pattern for callout entry stride calculation in x64:
        // imul rax, rbx, 0x50  (multiply calloutId by entry size 0x50)
        // commonly emitted when indexing into the flat callout array
        $stride_calc = { 48 6B ?? 50 }

        // Pattern for reading ClassifyFunction at +0x10 from callout entry:
        // mov rax, [rcx+10h] or mov rax, [rax+10h]
        $classify_read = { 48 8B 4? 10 }

        // IOCTL pattern for RTCore64 kernel R/W
        // 0xC3502808 in little-endian
        $ioctl_rtcore = { 08 28 50 C3 }

    condition:
        uint16(0) == 0x5A4D   // valid PE

        and filesize < 5MB

        and (
            // Strong signal: BYOVD + WFP enumeration + netio reference
            // Classic pattern of the full technique
            (
                1 of ($byovd_*)
                and 1 of ($fwpm_*)
                and 1 of ($netio_*)
                and $nt_sysmod
            )
            or
            // Strong signal: FeDefaultClassifyCallback referenced explicitly
            // Only appears in tooling that implements this specific patching technique
            (
                1 of ($fe_default_*)
                and 1 of ($byovd_*)
                and $devioctl
            )
            or
            // Strong signal: gWfpGlobal string + WFP enumeration + BYOVD
            (
                $wfp_global
                and 1 of ($fwpm_*)
                and 1 of ($byovd_*)
            )
            or
            // Medium signal: ALE layer GUIDs + BYOVD + kernel module enumeration
            // Covers implementations that don't keep strings but embed GUIDs
            (
                1 of ($ale_v4_guid, $ale_v6_guid)
                and 1 of ($byovd_*)
                and $nt_sysmod
                and $devioctl
            )
            or
            // Medium signal: callout stride + classify read pattern + WFP enumeration
            // Covers stripped binaries that removed strings but kept the math
            (
                $stride_calc
                and $classify_read
                and 1 of ($fwpm_*)
                and $devioctl
            )
        )
}
