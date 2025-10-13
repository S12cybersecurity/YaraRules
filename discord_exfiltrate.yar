rule 0x12_detect_winhttp_webhook_exfil
{
    meta:
        author = "0x12 Dark Development"
        description = "Heuristic detection of WinHTTP-based outbound webhook/JSON exfiltration (e.g. Discord-like)."
        date = "2025-10-13"
        version = "1.0"
        license = " defensive use only "

    strings:
        // WinHTTP API names (common imports or embedded strings)
        $s_winhttp_open        = "WinHttpOpen" wide ascii
        $s_winhttp_connect     = "WinHttpConnect" wide ascii
        $s_winhttp_openreq     = "WinHttpOpenRequest" wide ascii
        $s_winhttp_send        = "WinHttpSendRequest" wide ascii
        $s_winhttp_recv        = "WinHttpReceiveResponse" wide ascii
        $s_winhttp_query       = "WinHttpQueryHeaders" wide ascii

        // Common functions used for UTF-16 -> UTF-8 conversion
        $s_wctomb              = "WideCharToMultiByte" wide ascii

        // Indicators of JSON / webhooks / Discord-like usage
        $s_content_type        = "Content-Type: application/json" ascii wide
        $s_json_content_start  = "{\"content\":" ascii
        $s_discord_host        = "discord.com" ascii wide
        $s_api_webhooks_path   = "/api/webhooks/" ascii

    condition:
        // Heuristic: presence of WinHTTP usage AND (JSON/webhook indicator OR UTF conversion)
        ( ( $s_winhttp_open or $s_winhttp_connect or $s_winhttp_openreq or $s_winhttp_send or $s_winhttp_recv or $s_winhttp_query )
          and
          ( $s_content_type or $s_json_content_start or $s_discord_host or $s_api_webhooks_path or $s_wctomb )
        )
        // Optional sanity: avoid extremely large files
        and filesize < 10MB
}
