/*
 * ============================================================
 *  mod_adgroups.c — Module d'énumération des groupes AD (RDLL)
 *
 *  Port C natif du module .NET "GroupEnumerator" (équipe PFE 2026)
 *  Gère les membres explicites ET les membres primaires (RID).
 * ============================================================
 */
#include "beacon.h"
#include <string.h>
#include <stdio.h>
#include <windows.h>
#include <sddl.h> // Pour ConvertSidToStringSidA

#ifdef RDLL_MODE

#include <winldap.h>

/* Structure pour mapper les groupes primaires (RID -> Nom) */
typedef struct {
    int rid;
    char name[256];
} PrimaryGroupEntry;

static PrimaryGroupEntry primary_map[4096];
static int primary_count = 0;

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

/* ── Extraction du RID depuis un SID binaire ── */
static int get_rid_from_sid(PLDAP ld, PLDAPMessage entry) {
    char **vals = ldap_get_values(ld, entry, "objectSid");
    if (!vals || !vals[0]) return -1;

    PSTR sid_str = NULL;
    // Convertit le SID binaire en chaîne "S-1-5-21-...-RID"
    if (ConvertSidToStringSidA((PSID)vals[0], &sid_str)) {
        int rid = -1;
        char *last_dash = strrchr(sid_str, '-');
        if (last_dash) {
            rid = atoi(last_dash + 1);
        }
        LocalFree(sid_str);
        ldap_value_free(vals);
        return rid;
    }
    ldap_value_free(vals);
    return -1;
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

    /* ── Étape 1 : Construire la map des groupes primaires ── */
    const char *primary_filter = "(&(primaryGroupID=*)(|(objectClass=user)(objectClass=computer)))";
    char *primary_attrs[] = { "sAMAccountName", "primaryGroupID", NULL };
    PLDAPMessage primary_msg = NULL;

    if (ldap_search_s(ld, (PCHAR)base_dn, LDAP_SCOPE_SUBTREE, (PCHAR)primary_filter, primary_attrs, 0, &primary_msg) == LDAP_SUCCESS && primary_msg) {
        PLDAPMessage entry;
        for (entry = ldap_first_entry(ld, primary_msg); entry; entry = ldap_next_entry(ld, entry)) {
            char name[256] = {0};
            ad_get_prop(ld, entry, "sAMAccountName", name, sizeof(name));
            
            char **rid_vals = ldap_get_values(ld, entry, "primaryGroupID");
            if (rid_vals && rid_vals[0]) {
                int rid = atoi(rid_vals[0]);
                if (rid > 0 && primary_count < 4096) {
                    primary_map[primary_count].rid = rid;
                    strncpy(primary_map[primary_count].name, name, 255);
                    primary_count++;
                }
                ldap_value_free(rid_vals);
            }
        }
        ldap_msgfree(primary_msg);
    }

    /* ── Étape 2 : Rechercher tous les groupes ── */
    const char *group_filter = "(objectClass=group)";
    char *group_attrs[] = { "name", "sAMAccountName", "description", "member", "objectSid", NULL };
    PLDAPMessage group_msg = NULL;

    if (ldap_search_s(ld, (PCHAR)base_dn, LDAP_SCOPE_SUBTREE, (PCHAR)group_filter, group_attrs, 0, &group_msg) != LDAP_SUCCESS || !group_msg) {
        BeaconPrintf(CALLBACK_ERROR, "[AD] Requete groupes echouee");
        ldap_unbind_s(ld);
        return;
    }

    int group_count = 0;
    PLDAPMessage g_entry;
    for (g_entry = ldap_first_entry(ld, group_msg); g_entry; g_entry = ldap_next_entry(ld, g_entry)) {
        char name[256], sam[256], desc[512];
        ad_get_prop(ld, g_entry, "name", name, sizeof(name));
        ad_get_prop(ld, g_entry, "sAMAccountName", sam, sizeof(sam));
        ad_get_prop(ld, g_entry, "description", desc, sizeof(desc));

        int rid = get_rid_from_sid(ld, g_entry);
        
        // Buffer pour la liste des membres (8KB pour gérer les groupes nombreux)
        char members_list[8192] = {0};
        int member_count = 0;

        // 1. Ajouter les membres primaires (ex: tous les utilisateurs dans "Domain Users")
        if (rid > 0) {
            for (int i = 0; i < primary_count; i++) {
                if (primary_map[i].rid == rid) {
                    if (member_count > 0) strncat(members_list, ", ", sizeof(members_list) - strlen(members_list) - 1);
                    strncat(members_list, primary_map[i].name, sizeof(members_list) - strlen(members_list) - 1);
                    member_count++;
                }
            }
        }

        // 2. Ajouter les membres explicites (attribut 'member')
        char **member_dns = ldap_get_values(ld, g_entry, "member");
        if (member_dns) {
            for (int i = 0; member_dns[i] != NULL; i++) {
                PLDAPMessage m_msg = NULL;
                char *m_attrs[] = { "sAMAccountName", "objectClass", NULL };
                
                // Recherche ultra-rapide en SCOPE_BASE directement sur le DN
                if (ldap_search_s(ld, (PCHAR)member_dns[i], LDAP_SCOPE_BASE, "(objectClass=*)", m_attrs, 0, &m_msg) == LDAP_SUCCESS && m_msg) {
                    PLDAPMessage m_entry = ldap_first_entry(ld, m_msg);
                    if (m_entry) {
                        char m_name[256] = {0};
                        ad_get_prop(ld, m_entry, "sAMAccountName", m_name, sizeof(m_name));
                        
                        if (m_name[0] != '\0') {
                            // Vérification simple des doublons
                            if (strstr(members_list, m_name) == NULL) {
                                if (member_count > 0) strncat(members_list, ", ", sizeof(members_list) - strlen(members_list) - 1);
                                strncat(members_list, m_name, sizeof(members_list) - strlen(members_list) - 1);
                                member_count++;
                            }
                        }
                    }
                    ldap_msgfree(m_msg);
                }
            }
            ldap_value_free(member_dns);
        }

        group_count++;
        BeaconPrintf(CALLBACK_OUTPUT, "[%d] %s (%s)", group_count, name[0] ? name : sam, sam[0] ? sam : "?");
        if (desc[0] != '\0') {
            BeaconPrintf(CALLBACK_OUTPUT, "     Description: %s", desc);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "     Membres    : %s\n", member_count > 0 ? members_list : "Aucun (ou limite de buffer atteinte)");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "────────────────────────────────────────\nTotal        : %d groupe(s) AD\n", group_count);

    ldap_msgfree(group_msg);
    ldap_unbind_s(ld);
}

#else

BOF_DLL_EXPORT void go(char *args, int args_len) {
    (void)args; (void)args_len;
    BeaconPrintf(CALLBACK_ERROR, "[adgroups] Mode BOF non supporté — utilisez -t rdll");
}

#endif /* RDLL_MODE */