rule ldap_recon_activity_0x12_dark_development
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects generic LDAP/Active Directory enumeration techniques (DC discovery, LDAP bind, RootDSE queries, paged searches, SPN/UAC/time attributes). Not specific to a single source file."
        date = "2025-11-06"
        reference = "Generic detection for LDAP AD reconnaissance (DsGetDcNameW, ldap_bind, ldap_search, paged controls, defaultNamingContext, servicePrincipalName, userAccountControl)"
        tactic = "reconnaissance"
        technique = "Active Directory / LDAP enumeration"
        severity = "medium"

    strings:
        // Windows domain discovery
        $dsgetdc    = "DsGetDcNameW" wide ascii

        // Core LDAP APIs (wide and ascii)
        $ldap_init  = "ldap_initW" wide ascii
        $ldap_ssl   = "ldap_sslinitW" wide ascii
        $ldap_bind  = "ldap_bind_sW" wide ascii
        $ldap_search_base = "ldap_search_sW" wide ascii
        $ldap_search_ext  = "ldap_search_ext_sW" wide ascii

        // Paging controls and parsing
        $page_create = "ldap_create_page_controlW" wide ascii
        $page_parse  = "ldap_parse_page_controlW" wide ascii

        // SSPI / negotiate marker
        $negotiate   = "LDAP_AUTH_NEGOTIATE" wide ascii

        // Common AD attribute names used in recon
        $attr_defaultNC = "defaultNamingContext" wide ascii
        $attr_spn       = "servicePrincipalName" wide ascii
        $attr_uac       = "userAccountControl" wide ascii
        $attr_lastLogon = "lastLogonTimestamp" wide ascii
        $attr_pwdLast   = "pwdLastSet" wide ascii

    condition:
        // Require multiple LDAP-related APIs + at least one AD attribute name to reduce false positives.
        (3 of ($dsgetdc, $ldap_init, $ldap_ssl, $ldap_bind, $ldap_search_base, $ldap_search_ext, $page_create, $page_parse, $negotiate))
        and
        (1 of ($attr_defaultNC, $attr_spn, $attr_uac, $attr_lastLogon, $attr_pwdLast))
}
