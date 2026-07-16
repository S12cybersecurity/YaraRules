rule DirectMFTParsing_RawNTFSEnumeration
{
    meta:
        description   = "Detects binaries that perform direct $MFT parsing to enumerate NTFS filesystem entries, bypassing monitored API layers (FindFirstFile, NtQueryDirectoryFile)"
        author        = "0x12 Dark Development"
        reference     = "https://medium.com/@s12deff"
        created       = "2025-07-16"
        mitre_attack  = "T1083 - File and Directory Discovery"
        severity      = "high"
        confidence    = "medium"
        note          = "May also match legitimate low-level disk tools (defragmenters, forensic suites). Combine with behavioral context for higher fidelity."

    strings:

        // === Volume Handle Acquisition ===
        // CreateFileW / NtCreateFile paths used to open the raw volume device
        $vol_c    = "\\\\.\\C:" wide
        $vol_d    = "\\\\.\\D:" wide
        $vol_e    = "\\\\.\\E:" wide
        $vol_f    = "\\\\.\\F:" wide
        $vol_phys = "\\\\.\\PhysicalDrive" wide
        $vol_nt   = "\\??\\C:" wide         // NT native path alternative

        // === NTFS-Specific IOCTLs ===

        // FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064
        // Retrieves MFT start LCN, BytesPerFileRecordSegment,
        // BytesPerCluster, MftValidDataLength — required to locate and walk the $MFT
        $ioctl_nvd = { 64 00 09 00 }

        // FSCTL_GET_NTFS_FILE_RECORD = 0x00090068
        // Alternative approach: request individual MFT records by record number
        $ioctl_nfr = { 68 00 09 00 }

        // === MFT Record Internals ===

        // FRN 48-bit mask: 0x0000FFFFFFFFFFFF (little-endian QWORD)
        // Used to strip the sequence number field from file reference numbers.
        // Uniquely tied to $MFT record number handling — low false-positive rate.
        $frn_mask  = { FF FF FF FF FF FF 00 00 }

        // MFT record "FILE" signature = 0x454C4946 (little-endian DWORD)
        // Every MFT parser validates this at the start of each record
        $mft_sig   = { 46 49 4C 45 }

        // Attribute chain end marker: 0xFFFFFFFF as DWORD
        // Every MFT attribute walker must check this to stop iteration
        $attr_end  = { FF FF FF FF }

        // NTFS attribute type codes as DWORDs (little-endian)
        $attr_si   = { 10 00 00 00 }   // $STANDARD_INFORMATION
        $attr_fn   = { 30 00 00 00 }   // $FILE_NAME
        $attr_data = { 80 00 00 00 }   // $DATA

        // === Debug / Verbose Build Strings ===
        // These field names have no reason to appear outside of NTFS tools.
        // If present alongside an IOCTL — very high confidence.
        $s_lcn     = "MftStartLcn"
        $s_frs     = "BytesPerFileRecordSegment"
        $s_mft     = "$MFT"
        $s_mft_w   = "$MFT" wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (
            // --- Variant A | High Confidence ---
            // Core MFT bulk walker:
            // Opens raw volume + queries NTFS metadata + manipulates FRNs
            // This three-way combination is unique to direct $MFT traversal
            (
                (1 of ($vol_*)) and
                $ioctl_nvd and
                $frn_mask
            )
            or
            // --- Variant B | High Confidence ---
            // Attribute-level parser:
            // Validates "FILE" signature + walks attribute chain + strips FRN sequence numbers
            (
                $mft_sig and
                $frn_mask and
                ($ioctl_nvd or $ioctl_nfr) and
                (2 of ($attr_si, $attr_fn, $attr_data)) and
                $attr_end
            )
            or
            // --- Variant C | Medium Confidence ---
            // Per-record FSCTL approach:
            // Some implementations request records one by one instead of bulk reading
            (
                (1 of ($vol_*)) and
                $ioctl_nfr and
                $frn_mask
            )
            or
            // --- Variant D | High Confidence ---
            // Debug or verbose build:
            // NTFS internal struct field names have no reason to appear in non-NTFS software
            (
                ($s_lcn or $s_frs) and
                ($ioctl_nvd or $ioctl_nfr)
            )
            or
            // --- Variant E | Medium Confidence ---
            // Explicit $MFT string reference (format strings, error messages) + IOCTL + volume path
            (
                ($s_mft or $s_mft_w) and
                ($ioctl_nvd or $ioctl_nfr) and
                (1 of ($vol_*))
            )
        )
}
