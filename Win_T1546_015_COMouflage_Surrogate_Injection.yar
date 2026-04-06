rule Win_T1546_015_COMouflage_Surrogate_Injection {
    meta:
        author = "0x12 Dark Development"
        description = "Detects COM Surrogate injection technique (COMouflage) which weaponizes DLL Surrogates for process injection and parent PID masquerading."
        technique = "T1546.015 (Component Object Model Hijacking)"
        context = "https://0x12darkdev.net"
        date = "2026-04-06"
        severity = "High"

    strings:
        // Registry paths and keys critical to the technique
        $reg_appid = "Software\\Classes\\AppID\\" wide ascii
        $reg_clsid = "Software\\Classes\\CLSID\\" wide ascii
        $reg_inproc = "\\InprocServer32" wide ascii
        $val_surrogate = "DllSurrogate" wide ascii
        $val_threading = "ThreadingModel" wide ascii

        // API imports typically used to implement this
        $api_reg_create = "RegCreateKeyEx"
        $api_reg_set = "RegSetValueEx"
        $api_cocreate = "CoCreateInstance"
        $api_clside_str = "CLSIDFromString"

        // Hex for CLSCTX_LOCAL_SERVER (0x4) often passed to CoCreateInstance
        // This is a more behavioral indicator if found in code logic
        $hex_local_server = { 04 00 00 00 }

    condition:
        uint16(0) == 0x5A4D and // PE File
        (
            // Check for the combination of registry manipulation and COM instantiation
            (all of ($reg_*)) and 
            (all of ($val_*)) and
            (any of ($api_*)) and
            $hex_local_server
        ) or (
            // High confidence if it includes the specific logic for empty DllSurrogate strings
            $val_surrogate and $reg_appid and $api_reg_set
        )
}
