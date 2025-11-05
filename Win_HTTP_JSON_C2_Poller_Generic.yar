rule Win_HTTP_JSON_C2_Poller_Generic
{
    meta:
        author      = "0x12 Dark Development"
        description = "Detects generic WinHTTP-based JSON polling C2 that executes commands and posts results"
        date        = "2025-11-05"
        version     = "1.0"
        reference   = "Technique-focused; not tied to one hash"

    strings:
        // --- WinHTTP workflow (names as plain strings to survive stripped IATs) ---
        $http.open          = "WinHttpOpen" ascii
        $http.connect       = "WinHttpConnect" ascii
        $http.open_req      = "WinHttpOpenRequest" ascii
        $http.send          = "WinHttpSendRequest" ascii
        $http.recv          = "WinHttpReceiveResponse" ascii
        $http.read          = "WinHttpReadData" ascii
        $http.avail         = "WinHttpQueryDataAvailable" ascii
        $http.close         = "WinHttpCloseHandle" ascii

        // --- JSON over HTTP markers ---
        $json.ct            = "Content-Type: application/json" ascii wide nocase
        $json.get           = "GET" ascii wide
        $json.post          = "POST" ascii wide
        $json.cmd_key       = "\"command\"" ascii // common control-plane key
        $json.output_key    = "\"output\""  ascii
        $json.escape_regex  = /\\u[0-9A-Fa-f]{4}/ ascii       // typical JSON escape pattern

        // --- Polling-style paths (loose indicators; common in simple C2s) ---
        $path.command       = "/command" ascii wide
        $path.output        = "/output"  ascii wide

        // --- Command execution primitives ---
        $exec.popen         = "_popen" ascii
        $exec.createprocA   = "CreateProcessA" ascii
        $exec.createprocW   = "CreateProcessW" ascii

        // --- Looping / timing hints (often used in pollers) ---
        $sleep              = "Sleep" ascii

        // --- Optional ‘nice-to-have’ markers (low weight; do not rely on alone) ---
        $ua.hint            = "WinHTTP" ascii wide
        $ua.custom          = "Command Client" ascii wide

    condition:
        // Windows PE (32- or 64-bit)
        pe and
        (pe.machine == pe.MACHINE_I386 or pe.machine == pe.MACHINE_AMD64) and

        // Prefer samples that clearly look like WinHTTP clients:
        (
          // Either imports explicitly show WinHTTP usage...
          (pe.imports("winhttp.dll", "WinHttpOpen") and
           pe.imports("winhttp.dll", "WinHttpConnect") and
           pe.imports("winhttp.dll", "WinHttpOpenRequest"))
          // ...or the strings strongly suggest WinHTTP API presence even if imports are munged/stripped.
          or (2 of ($http.*))
        ) and

        // Evidence of JSON-over-HTTP command channel (verbs/headers/keys/escapes/paths)
        ( (2 of ($json.*)) and (1 of ($path.*)) ) and

        // Some way to execute the received command (pipe or CreateProcess)
        ( $exec.popen or 1 of ($exec.createproc*) ) and

        // A bit more confidence via auxiliary hints (loop/sleep or UA-ish strings)
        ( $sleep or 1 of ($ua.*) )
}
