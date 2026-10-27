/*
 * ============================================================
 *  mod_adcomputers.c — Module d'énumération AD (RDLL)
 *
 *  Port C du module .NET "ComputerEnumerator" (équipe PFE 2026)
 *  Compatible avec l'API Windows LDAP (winldap.h)
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
    /* Cast en (PCHAR) pour satisfaire winldap.h */
    char **vals = ldap_get_values(ld, entry, (PCHAR)prop);
    if (vals && vals[0]) {
        strncpy(out, vals[0], outsz - 1);
        out[outsz - 1] = '\0';
    }
    if (vals)
        ldap_value_free(vals);
}

/* ── Construction du base DN depuis le nom DNS du domaine ──────
 *  "corp.local" → "DC=corp,DC=local"
 * ────────────────────────────────────────────────────────────── */
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
            "adcomputers requiert une machine AD");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Domaine      : %s\n", domain);

    /* ── 2. Base DN : DC=x,DC=y ────────────────────────────── */
    char base_dn[512];
    ad_build_base_dn(domain, base_dn, sizeof(base_dn));
    BeaconPrintf(CALLBACK_OUTPUT, "Base DN      : %s\n", base_dn);

    /* ── 3. Connexion LDAP au DC ───────────────────────────── */
    /* ldap_init prend le nom d'hôte (le domaine) et le port */
    PLDAP ld = ldap_init((PCHAR)domain, LDAP_PORT);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR,
            "[AD] ldap_init echoue pour le domaine %s", domain);
        return;
    }

    /* ldap_connect attend une structure l_timeval pour le timeout */
    struct l_timeval timeout = { 5, 0 }; // 5 secondes
    ULONG rc = ldap_connect(ld, &timeout);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "[AD] Connexion LDAP echouee (code %lu)", rc);
        ldap_unbind_s(ld); /* Un seul argument sous Windows */
        return;
    }

     /* --- AJOUT ICI : Authentification via le contexte de sécurité courant --- */
    ULONG rc_bind = ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc_bind != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[AD] Echec de l'authentification LDAP (bind) (code %lu)", rc_bind);
        ldap_unbind_s(ld);
        return;
    }

    /* ── 4. Requête : tous les ordinateurs du domaine ──────── */
    const char *filter = "(objectClass=computer)";
    /* Tableau de pointeurs non-const pour être compatible avec PCHAR attrs[] */
    char *attrs[] = {
        "name",
        "sAMAccountName",
        "dNSHostName",
        "operatingSystem",
        "operatingSystemVersion",
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

        char name[256], sam[256], dns[256], os[128], osv[64];
        ad_get_prop(ld, entry, "name", name, sizeof(name));
        ad_get_prop(ld, entry, "sAMAccountName", sam, sizeof(sam));
        ad_get_prop(ld, entry, "dNSHostName", dns, sizeof(dns));
        ad_get_prop(ld, entry, "operatingSystem", os, sizeof(os));
        ad_get_prop(ld, entry, "operatingSystemVersion", osv, sizeof(osv));

        count++;
        BeaconPrintf(CALLBACK_OUTPUT,
            "[%d] %s\n", count, name[0] ? name : "?");
        BeaconPrintf(CALLBACK_OUTPUT,
            "     sAMAccountName : %s\n", sam[0] ? sam : "-");
        BeaconPrintf(CALLBACK_OUTPUT,
            "     dNSHostName    : %s\n", dns[0] ? dns : "-");
        BeaconPrintf(CALLBACK_OUTPUT,
            "     OS             : %s %s\n",
            os[0] ? os : "?", osv[0] ? osv : "");
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "────────────────────────────────────────\n"
        "Total        : %d ordinateur(s) AD\n", count);

    /* ── 6. Nettoyage ──────────────────────────────────────── */
    ldap_msgfree(mesg);
    ldap_unbind_s(ld); /* Un seul argument sous Windows */
}

#else /* ── BOF mode : non supporté pour ce module ─────────────── */

BOF_DLL_EXPORT void go(char *args, int args_len) {
    (void)args;
    (void)args_len;
    BeaconPrintf(CALLBACK_ERROR,
        "[adcomputers] Mode BOF non supporté — utilisez -t rdll");
}

#endif /* RDLL_MODE */