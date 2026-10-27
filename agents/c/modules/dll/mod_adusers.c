/*
 * ============================================================
 *  mod_adusers.c — Module d'énumération des utilisateurs AD (RDLL)
 *
 *  Port C natif du module .NET "UserEnumerator" (équipe PFE 2026)
 *
 *  Fonction :
 *    Enumère les utilisateurs du domaine Active Directory
 *    courant via une requête LDAP.
 *
 *  Propriétés par utilisateur :
 *    displayName, sAMAccountName, userPrincipalName, description
 *
 *  Auteur  : Équipe PFE (port C du module .NET)
 *  Date    : 2026
 *  Projet  : Framework C2 Modulaire — PFE INPT 2026
 * ============================================================
 */
#include "beacon.h"
#include <string.h>
#include <stdio.h>

#ifdef RDLL_MODE

#include <winldap.h>

/* ── Extraction d'une propriété LDAP vers un buffer appelant ── */
static void ad_get_prop(PLDAP ld, PLDAPMessage entry,
                        const char *prop, char *out, size_t outsz) {
    out[0] = '\0';
    char **vals = ldap_get_values(ld, entry, (PCHAR)prop);
    if (vals && vals[0]) {
        strncpy(out, vals[0], outsz - 1);
        out[outsz - 1] = '\0';
    }
    if (vals)
        ldap_value_free(vals);
}

/* ── Construction du base DN depuis le nom DNS du domaine ────── */
static void ad_build_base_dn(const char *domain, char *out, size_t outsz) {
    out[0] = '\0';
    const char *p = domain;
    for (;;) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);

        if (out[0] != '\0')
            strncat(out, ",", outsz - strlen(out) - 1);
        strncat(out, "DC=", outsz - strlen(out) - 1);
        strncat(out, p, len);

        if (!dot)
            break;
        p = dot + 1;
    }
}

/* ============================================================
 *  POINT D'ENTRÉE
 * ============================================================ */
BOF_DLL_EXPORT void go(char *args, int args_len) {
    (void)args;
    (void)args_len;

    /* ── 1. Nom du domaine courant (DNS) ───────────────────── */
    char domain[256] = {0};
    DWORD sz = (DWORD)sizeof(domain);
    if (!GetComputerNameExA(ComputerNameDnsDomain, domain, &sz)
        || domain[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR,
            "[AD] Machine non jointe au domaine (WORKGROUP) — "
            "adusers requiert une machine AD");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Domaine      : %s\n", domain);

    /* ── 2. Base DN : DC=x,DC=y ────────────────────────────── */
    char base_dn[512];
    ad_build_base_dn(domain, base_dn, sizeof(base_dn));
    BeaconPrintf(CALLBACK_OUTPUT, "Base DN      : %s\n", base_dn);

    /* ── 3. Connexion LDAP au DC ───────────────────────────── */
    PLDAP ld = ldap_init((PCHAR)domain, LDAP_PORT);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[AD] ldap_init echoue pour le domaine %s", domain);
        return;
    }

    struct l_timeval timeout = { 5, 0 }; 
    ULONG rc = ldap_connect(ld, &timeout);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[AD] Connexion LDAP echouee (code %lu)", rc);
        ldap_unbind_s(ld);
        return;
    }

    /* Authentification via le contexte de sécurité courant (SSPI) */
    ULONG rc_bind = ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc_bind != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[AD] Echec de l'authentification LDAP (bind) (code %lu)", rc_bind);
        ldap_unbind_s(ld);
        return;
    }

    /* ── 4. Requête : tous les utilisateurs du domaine ─────── */
    const char *filter = "(&(objectClass=user)(objectCategory=person))";
    char *attrs[] = {
        "displayName",
        "sAMAccountName",
        "userPrincipalName",
        "description",
        NULL
    };

    PLDAPMessage mesg = NULL;
    rc = ldap_search_s(ld, (PCHAR)base_dn, LDAP_SCOPE_SUBTREE,
                       (PCHAR)filter, attrs, 0, &mesg);
    if (rc != LDAP_SUCCESS || !mesg) {
        BeaconPrintf(CALLBACK_ERROR,
            "[AD] Requete LDAP echouee (code %lu) — "
            "verifiez le compte et la connectivite au DC", rc);
        ldap_unbind_s(ld);
        return;
    }

    /* ── 5. Iteration des resultats ─────────────────────────── */
    int count = 0;
    PLDAPMessage entry;
    for (entry = ldap_first_entry(ld, mesg); entry;
         entry = ldap_next_entry(ld, entry)) {

        char display_name[256], sam[256], upn[256], desc[512];
        ad_get_prop(ld, entry, "displayName", display_name, sizeof(display_name));
        ad_get_prop(ld, entry, "sAMAccountName", sam, sizeof(sam));
        ad_get_prop(ld, entry, "userPrincipalName", upn, sizeof(upn));
        ad_get_prop(ld, entry, "description", desc, sizeof(desc));

        count++;
        BeaconPrintf(CALLBACK_OUTPUT,
            "[%d] %s (%s)\n", count, 
            display_name[0] ? display_name : sam, 
            sam[0] ? sam : "?");
        
        if (upn[0] != '\0') {
            BeaconPrintf(CALLBACK_OUTPUT, "     UPN        : %s\n", upn);
        }
        if (desc[0] != '\0') {
            BeaconPrintf(CALLBACK_OUTPUT, "     Description: %s\n", desc);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "────────────────────────────────────────\n"
        "Total        : %d utilisateur(s) AD\n", count);

    /* ── 6. Nettoyage ──────────────────────────────────────── */
    ldap_msgfree(mesg);
    ldap_unbind_s(ld);
}

#else /* ── BOF mode : non supporté pour ce module ─────────────── */

BOF_DLL_EXPORT void go(char *args, int args_len) {
    (void)args;
    (void)args_len;
    BeaconPrintf(CALLBACK_ERROR,
        "[adusers] Mode BOF non supporté — utilisez -t rdll");
}

#endif /* RDLL_MODE */