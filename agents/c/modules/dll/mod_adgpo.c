/*
 * ============================================================
 *  mod_adgpo.c — Module d'énumération des GPO AD (RDLL)
 *
 *  Port C natif du module .NET "GpoEnumerator" (équipe PFE 2026)
 *  Mappe les GPO aux OU via l'analyse de l'attribut gPLink.
 * ============================================================
 */
#include "beacon.h"
#include <string.h>
#include <stdio.h>
#include <windows.h>

#ifdef RDLL_MODE

#include <winldap.h>

#define MAX_GPO_LINKS 2048

typedef struct {
    char guid[64];
    char ou_name[256];
} GpoLink;

static GpoLink gpo_links[MAX_GPO_LINKS];
static int gpo_link_count = 0;

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

    /* ── Étape 1 : Construire la map GPO GUID -> OU Name ── */
    const char *ou_filter = "(objectClass=organizationalUnit)";
    char *ou_attrs[] = { "name", "gPLink", NULL };
    PLDAPMessage ou_msg = NULL;

    if (ldap_search_s(ld, (PCHAR)base_dn, LDAP_SCOPE_SUBTREE, (PCHAR)ou_filter, ou_attrs, 0, &ou_msg) == LDAP_SUCCESS && ou_msg) {
        PLDAPMessage ou_entry;
        for (ou_entry = ldap_first_entry(ld, ou_msg); ou_entry; ou_entry = ldap_next_entry(ld, ou_entry)) {
            char ou_name[256] = {0};
            ad_get_prop(ld, ou_entry, "name", ou_name, sizeof(ou_name));
            if (ou_name[0] == '\0') {
                ad_get_prop(ld, ou_entry, "ou", ou_name, sizeof(ou_name));
            }
            if (ou_name[0] == '\0') continue;

            char **gplink_vals = ldap_get_values(ld, ou_entry, "gPLink");
            if (gplink_vals && gplink_vals[0]) {
                char *p = gplink_vals[0];
                // Parse le format : [LDAP://CN={GUID},CN=Policies...;0]
                while ((p = strchr(p, '{')) != NULL) {
                    char *end = strchr(p, '}');
                    if (end) {
                        size_t len = end - p + 1;
                        if (len < sizeof(char[64])) {
                            char guid[64] = {0};
                            strncpy(guid, p, len);
                            
                            // Vérifier les doublons (même GUID + même OU)
                            int exists = 0;
                            for (int i = 0; i < gpo_link_count; i++) {
                                if (_stricmp(gpo_links[i].guid, guid) == 0 && _stricmp(gpo_links[i].ou_name, ou_name) == 0) {
                                    exists = 1;
                                    break;
                                }
                            }
                            
                            if (!exists && gpo_link_count < MAX_GPO_LINKS) {
                                strncpy(gpo_links[gpo_link_count].guid, guid, 63);
                                strncpy(gpo_links[gpo_link_count].ou_name, ou_name, 255);
                                gpo_link_count++;
                            }
                        }
                        p = end + 1;
                    } else {
                        break;
                    }
                }
                ldap_value_free(gplink_vals);
            }
        }
        ldap_msgfree(ou_msg);
    }

    /* ── Étape 2 : Rechercher toutes les GPO ── */
    const char *gpo_filter = "(objectClass=groupPolicyContainer)";
    char *gpo_attrs[] = { "displayName", "name", "gPCFileSysPath", NULL };
    PLDAPMessage gpo_msg = NULL;

    if (ldap_search_s(ld, (PCHAR)base_dn, LDAP_SCOPE_SUBTREE, (PCHAR)gpo_filter, gpo_attrs, 0, &gpo_msg) != LDAP_SUCCESS || !gpo_msg) {
        BeaconPrintf(CALLBACK_ERROR, "[AD] Requete GPO echouee");
        ldap_unbind_s(ld);
        return;
    }

    int gpo_count = 0;
    PLDAPMessage gpo_entry;
    for (gpo_entry = ldap_first_entry(ld, gpo_msg); gpo_entry; gpo_entry = ldap_next_entry(ld, gpo_entry)) {
        char display_name[256] = {0};
        char guid[64] = {0};
        char gpc_path[512] = {0};

        ad_get_prop(ld, gpo_entry, "displayName", display_name, sizeof(display_name));
        ad_get_prop(ld, gpo_entry, "name", guid, sizeof(guid));
        ad_get_prop(ld, gpo_entry, "gPCFileSysPath", gpc_path, sizeof(gpc_path));

        // Construire la liste des OU appliquées pour cette GPO
        char applied_to[4096] = {0};
        for (int i = 0; i < gpo_link_count; i++) {
            if (_stricmp(gpo_links[i].guid, guid) == 0) {
                if (applied_to[0] != '\0') {
                    strncat(applied_to, ", ", sizeof(applied_to) - strlen(applied_to) - 1);
                }
                strncat(applied_to, gpo_links[i].ou_name, sizeof(applied_to) - strlen(applied_to) - 1);
            }
        }

        gpo_count++;
        BeaconPrintf(CALLBACK_OUTPUT, "[%d] %s (%s)", gpo_count, display_name[0] ? display_name : guid, guid);
        if (gpc_path[0] != '\0') {
            BeaconPrintf(CALLBACK_OUTPUT, "     SYSVOL Path: %s", gpc_path);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "     Applied To : %s\n", applied_to[0] ? applied_to : "Aucune OU liee");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "────────────────────────────────────────\nTotal        : %d GPO(s) AD\n", gpo_count);

    ldap_msgfree(gpo_msg);
    ldap_unbind_s(ld);
}

#else

BOF_DLL_EXPORT void go(char *args, int args_len) {
    (void)args; (void)args_len;
    BeaconPrintf(CALLBACK_ERROR, "[adgpo] Mode BOF non supporté — utilisez -t rdll");
}

#endif /* RDLL_MODE */