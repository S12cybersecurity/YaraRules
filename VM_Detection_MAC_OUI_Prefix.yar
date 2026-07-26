rule VM_Detection_MAC_OUI_Prefix
{
    meta:
        description = "Detects binaries performing VM detection via MAC address OUI prefix matching"
        author      = "0x12 Dark Development"
        reference   = "https://0x12darkdev.net"

    strings:
        // GetAdaptersInfo import string
        $api = "GetAdaptersInfo" ascii wide

        // VMware OUI prefixes
        $oui_vmware1   = { 00 0C 29 }
        $oui_vmware2   = { 00 50 56 }

        // VirtualBox OUI
        $oui_vbox      = { 08 00 27 }

        // Parallels OUI
        $oui_parallels = { 00 1C 42 }

        // Hyper-V OUI prefixes
        $oui_hyperv1   = { 00 03 FF }
        $oui_hyperv2   = { 00 15 5D }

    condition:
        uint16(0) == 0x5A4D and        // MZ header
        $api and
        3 of ($oui_*)
}
