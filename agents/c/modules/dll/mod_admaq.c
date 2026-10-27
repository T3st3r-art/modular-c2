/*
 * ============================================================
 *  mod_admaq.c — Module d'énumération du MachineAccountQuota AD
 *
 *  Port C natif du module .NET "MachineAccountQuotaEnumerator" 
 *  Cible : Attribut ms-DS-MachineAccountQuota de l'objet domaine.
 *  Objectif Red Team : Vérifier si un utilisateur standard peut ajouter 
 *  des machines au domaine (valeur par défaut = 10), prérequis pour 
 *  des attaques comme Resource-Based Constrained Delegation (RBCD).
 * ============================================================
 */
#include "beacon.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#ifdef RDLL_MODE

#include <winldap.h>

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

    /* ── Requête : Objet domaine pour ms-DS-MachineAccountQuota ── */
    const char *filter = "(objectClass=domain)";
    char *attrs[] = { "ms-DS-MachineAccountQuota", NULL };

    PLDAPMessage msg = NULL;
    if (ldap_search_s(ld, (PCHAR)base_dn, LDAP_SCOPE_SUBTREE, (PCHAR)filter, attrs, 0, &msg) != LDAP_SUCCESS || !msg) {
        BeaconPrintf(CALLBACK_ERROR, "[AD] Requete MachineAccountQuota echouee");
        ldap_unbind_s(ld);
        return;
    }

    PLDAPMessage entry = ldap_first_entry(ld, msg);
    if (!entry) {
        BeaconPrintf(CALLBACK_ERROR, "[AD] Objet domaine non trouve");
        ldap_msgfree(msg);
        ldap_unbind_s(ld);
        return;
    }

    /* ── Extraction de la valeur ── */
    int maq = 10; /* Valeur par défaut historique d'Active Directory */
    char **vals = ldap_get_values(ld, entry, "ms-DS-MachineAccountQuota");
    if (vals && vals[0]) {
        maq = atoi(vals[0]);
        ldap_value_free(vals);
    }

    /* ── Affichage et analyse tactique automatique ── */
    BeaconPrintf(CALLBACK_OUTPUT, "MachineAccountQuota (ms-DS-MachineAccountQuota) : %d", maq);
    
    if (maq > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  [!] VULNERABILITE : Tout utilisateur authentifie peut ajouter jusqu'a %d machines au domaine.", maq);
        BeaconPrintf(CALLBACK_OUTPUT, "  [!] Cela permet des attaques de type Resource-Based Constrained Delegation (RBCD).");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "  [+] SECURISE : L'ajout de machines par les utilisateurs standards est desactive (0).");
    }

    ldap_msgfree(msg);
    ldap_unbind_s(ld);
}

#else

BOF_DLL_EXPORT void go(char *args, int args_len) {
    (void)args; (void)args_len;
    BeaconPrintf(CALLBACK_ERROR, "[admaq] Mode BOF non supporté — utilisez -t rdll");
}

#endif /* RDLL_MODE */