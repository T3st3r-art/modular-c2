/*
 * ============================================================
 *  mod_adou.c — Module d'énumération des Unités d'Organisation (OU) AD
 *
 *  Port C natif du module .NET "OuEnumerator" (équipe PFE 2026)
 *  Optimisation : Utilise LDAP_SCOPE_ONELEVEL pour récupérer 
 *  uniquement les enfants directs sans charger tout l'annuaire en mémoire.
 * ============================================================
 */
#include "beacon.h"
#include <string.h>
#include <stdio.h>
#include <windows.h>

#ifdef RDLL_MODE

#include <winldap.h>

#define MAX_CHILDREN 2000

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

/* ── Vérification du type d'objet via objectClass ── */
static int has_object_class(PLDAP ld, PLDAPMessage entry, const char *target_class) {
    char **vals = ldap_get_values(ld, entry, "objectClass");
    if (vals) {
        for (int i = 0; vals[i] != NULL; i++) {
            if (_stricmp(vals[i], target_class) == 0) {
                ldap_value_free(vals);
                return 1;
            }
        }
        ldap_value_free(vals);
    }
    return 0;
}

static int is_user(PLDAP ld, PLDAPMessage entry) {
    return has_object_class(ld, entry, "user") && !has_object_class(ld, entry, "computer");
}
static int is_computer(PLDAP ld, PLDAPMessage entry) { return has_object_class(ld, entry, "computer"); }
static int is_group(PLDAP ld, PLDAPMessage entry) { return has_object_class(ld, entry, "group"); }
static int is_ou(PLDAP ld, PLDAPMessage entry) { return has_object_class(ld, entry, "organizationalUnit"); }

/* ── Comparateur pour qsort (tri alphabétique) ── */
static int compare_strings(const void *a, const void *b) {
    return _stricmp(*(const char **)a, *(const char **)b);
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

    /* ── Étape 1 : Rechercher toutes les OU ── */
    const char *ou_filter = "(objectClass=organizationalUnit)";
    char *ou_attrs[] = { "ou", "name", "description", "distinguishedName", NULL };
    PLDAPMessage ou_msg = NULL;

    if (ldap_search_s(ld, (PCHAR)base_dn, LDAP_SCOPE_SUBTREE, (PCHAR)ou_filter, ou_attrs, 0, &ou_msg) != LDAP_SUCCESS || !ou_msg) {
        BeaconPrintf(CALLBACK_ERROR, "[AD] Requete OU echouee");
        ldap_unbind_s(ld);
        return;
    }

    int ou_count = 0;
    PLDAPMessage ou_entry;
    for (ou_entry = ldap_first_entry(ld, ou_msg); ou_entry; ou_entry = ldap_next_entry(ld, ou_entry)) {
        char ou_name[256] = {0}, desc[512] = {0}, ou_dn[512] = {0};
        
        ad_get_prop(ld, ou_entry, "ou", ou_name, sizeof(ou_name));
        if (ou_name[0] == '\0') {
            ad_get_prop(ld, ou_entry, "name", ou_name, sizeof(ou_name));
        }
        ad_get_prop(ld, ou_entry, "description", desc, sizeof(desc));
        ad_get_prop(ld, ou_entry, "distinguishedName", ou_dn, sizeof(ou_dn));

        if (ou_dn[0] == '\0') continue;

        /* ── Étape 2 : Récupérer les enfants directs de cette OU (ONELEVEL) ── */
        char *child_attrs[] = { "sAMAccountName", "ou", "name", "objectClass", NULL };
        PLDAPMessage child_msg = NULL;
        
        // Stockage temporaire pour le tri
        char *u_list[MAX_CHILDREN], *c_list[MAX_CHILDREN], *g_list[MAX_CHILDREN], *o_list[MAX_CHILDREN];
        int u_cnt = 0, c_cnt = 0, g_cnt = 0, o_cnt = 0;
        
        // Buffers statiques pour éviter trop de malloc
        static char u_buf[MAX_CHILDREN][256], c_buf[MAX_CHILDREN][256], g_buf[MAX_CHILDREN][256], o_buf[MAX_CHILDREN][256];

        if (ldap_search_s(ld, (PCHAR)ou_dn, LDAP_SCOPE_ONELEVEL, 
                          "(|(objectClass=user)(objectClass=computer)(objectClass=group)(objectClass=organizationalUnit))", 
                          child_attrs, 0, &child_msg) == LDAP_SUCCESS && child_msg) {
            
            PLDAPMessage child_entry;
            for (child_entry = ldap_first_entry(ld, child_msg); child_entry; child_entry = ldap_next_entry(ld, child_entry)) {
                char c_name[256] = {0};

                if (is_user(ld, child_entry)) {
                    ad_get_prop(ld, child_entry, "sAMAccountName", c_name, sizeof(c_name));
                    if (c_name[0] && u_cnt < MAX_CHILDREN) { strncpy(u_buf[u_cnt], c_name, 255); u_list[u_cnt++] = u_buf[u_cnt-1]; }
                } else if (is_computer(ld, child_entry)) {
                    ad_get_prop(ld, child_entry, "sAMAccountName", c_name, sizeof(c_name));
                    if (c_name[0] && c_cnt < MAX_CHILDREN) { strncpy(c_buf[c_cnt], c_name, 255); c_list[c_cnt++] = c_buf[c_cnt-1]; }
                } else if (is_group(ld, child_entry)) {
                    ad_get_prop(ld, child_entry, "sAMAccountName", c_name, sizeof(c_name));
                    if (c_name[0] && g_cnt < MAX_CHILDREN) { strncpy(g_buf[g_cnt], c_name, 255); g_list[g_cnt++] = g_buf[g_cnt-1]; }
                } else if (is_ou(ld, child_entry)) {
                    ad_get_prop(ld, child_entry, "ou", c_name, sizeof(c_name));
                    if (c_name[0] == '\0') ad_get_prop(ld, child_entry, "name", c_name, sizeof(c_name));
                    if (c_name[0] && o_cnt < MAX_CHILDREN) { strncpy(o_buf[o_cnt], c_name, 255); o_list[o_cnt++] = o_buf[o_cnt-1]; }
                }
            }
            ldap_msgfree(child_msg);
        }

        /* ── Étape 3 : Tri et formatage de la sortie ── */
        qsort(u_list, u_cnt, sizeof(char*), compare_strings);
        qsort(c_list, c_cnt, sizeof(char*), compare_strings);
        qsort(g_list, g_cnt, sizeof(char*), compare_strings);
        qsort(o_list, o_cnt, sizeof(char*), compare_strings);

        char childs_str[4096] = {0};
        int first = 1;
        
        for (int i = 0; i < u_cnt; i++) { if (!first) strncat(childs_str, ", ", sizeof(childs_str)-strlen(childs_str)-1); strncat(childs_str, u_list[i], sizeof(childs_str)-strlen(childs_str)-1); first = 0; }
        for (int i = 0; i < c_cnt; i++) { if (!first) strncat(childs_str, ", ", sizeof(childs_str)-strlen(childs_str)-1); strncat(childs_str, c_list[i], sizeof(childs_str)-strlen(childs_str)-1); first = 0; }
        for (int i = 0; i < g_cnt; i++) { if (!first) strncat(childs_str, ", ", sizeof(childs_str)-strlen(childs_str)-1); strncat(childs_str, g_list[i], sizeof(childs_str)-strlen(childs_str)-1); first = 0; }
        for (int i = 0; i < o_cnt; i++) { if (!first) strncat(childs_str, ", ", sizeof(childs_str)-strlen(childs_str)-1); strncat(childs_str, o_list[i], sizeof(childs_str)-strlen(childs_str)-1); first = 0; }

        ou_count++;
        BeaconPrintf(CALLBACK_OUTPUT, "[%d] %s", ou_count, ou_name[0] ? ou_name : "Sans nom");
        if (desc[0] != '\0') {
            BeaconPrintf(CALLBACK_OUTPUT, "     Description  : %s", desc);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "     Enfants      : %s\n", childs_str[0] ? childs_str : "Aucun");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "────────────────────────────────────────\nTotal        : %d OU(s) AD\n", ou_count);

    ldap_msgfree(ou_msg);
    ldap_unbind_s(ld);
}

#else

BOF_DLL_EXPORT void go(char *args, int args_len) {
    (void)args; (void)args_len;
    BeaconPrintf(CALLBACK_ERROR, "[adou] Mode BOF non supporté — utilisez -t rdll");
}

#endif /* RDLL_MODE */