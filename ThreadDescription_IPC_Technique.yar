rule ThreadDescription_IPC_Technique {
    meta:
        author = "0x12 Dark Development"
        description = "Detects the use of SetThreadDescription and GetThreadDescription, often employed for covert Inter-Process Communication (IPC)."
        date = "2025-12-03"
        reference = "Malware techniques database"
        
    strings:
        // Key API calls for setting and getting the description
        $set_desc = "SetThreadDescription" ascii wide nocase
        $get_desc = "GetThreadDescription" ascii wide nocase
        
        // API call required to open a handle to an external thread
        $open_thread = "OpenThread" ascii wide nocase
        
        // Common string constants used for the IPC channel name
        // (Optional: can be too specific, but useful for initial detection)
        $ipc_name1 = "IPC" wide
        $ipc_name2 = "IPC2" wide
        
    condition:
        // The core requirement: the code must use both Set and Get description functions.
        // Adding OpenThread increases confidence that it is targeting an external thread.
        ($set_desc and $get_desc) and $open_thread
}
