/*
 * ============================================================
 *  mod_adpwdpolicy.c — Module d'énumération de la politique de mot de passe AD
 *
 *  Port C natif du module .NET "PasswordPolicyEnumerator" (PFE 2026)
 *  Gère la conversion des Large Integers AD (ticks négatifs) en jours/minutes.
 * ============================================================
 */
#include "beacon.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#ifdef RDLL_MODE

#include <winldap.h>

/* ── Construction du base DN (DC=x,DC=y) ── */
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

/* ── Extraction d'une propriété entière ── */
static int get_int_prop(PLDAP ld, PLDAPMessage entry, const char *prop, int default_val) {
    char **vals = ldap_get_values(ld, entry, (PCHAR)prop);
    if (vals && vals[0]) {
        int val = atoi(vals[0]);
        ldap_value_free(vals);
        return val;
    }
    return default_val;
}

/* ── Extraction d'un Large Integer AD (retourné en chaîne par LDAP) ── */
static long long get_large_int_prop(PLDAP ld, PLDAPMessage entry, const char *prop) {
    char **vals = ldap_get_values(ld, entry, (PCHAR)prop);
    if (vals && vals[0]) {
        long long val = atoll(vals[0]);
        ldap_value_free(vals);
        return val;
    }
    return 0;
}

/* ── Conversion FileTime AD (ticks négatifs) en jours ── */
static int filetime_to_days(long long ft) {
    if (ft == 0) return 0;
    return (int)(llabs(ft) / 10000000LL / 86400LL);
}

/* ── Conversion FileTime AD (ticks négatifs) en minutes ── */
static int filetime_to_minutes(long long ft) {
    if (ft == 0) return 0;
    return (int)(llabs(ft) / 10000000LL / 60LL);
}

/* ── Décodage du bitmask pwdProperties ── */
static void decode_pwd_properties(int value, char *out, size_t outsz) {
    out[0] = '\0';
    int first = 1;
    
    if (value & 1)  { strncat(out, "DOMAIN_PASSWORD_COMPLEX", outsz - strlen(out) - 1); first = 0; }
    if (value & 2)  { if (!first) strncat(out, ", ", outsz - strlen(out) - 1); strncat(out, "DOMAIN_PASSWORD_NO_ANON_CHANGE", outsz - strlen(out) - 1); first = 0; }
    if (value & 4)  { if (!first) strncat(out, ", ", outsz - strlen(out) - 1); strncat(out, "DOMAIN_PASSWORD_NO_CLEAR_CHANGE", outsz - strlen(out) - 1); first = 0; }
    if (value & 8)  { if (!first) strncat(out, ", ", outsz - strlen(out) - 1); strncat(out, "DOMAIN_PASSWORD_LOCKOUT_ADMINS", outsz - strlen(out) - 1); first = 0; }
    if (value & 16) { if (!first) strncat(out, ", ", outsz - strlen(out) - 1); strncat(out, "DOMAIN_PASSWORD_STORE_CLEARTEXT", outsz - strlen(out) - 1); first = 0; }
    if (value & 32) { if (!first) strncat(out, ", ", outsz - strlen(out) - 1); strncat(out, "DOMAIN_REFUSE_PASSWORD_CHANGE", outsz - strlen(out) - 1); first = 0; }
    
    if (first) {
        snprintf(out, outsz, "%d", value);
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

    BeaconPrintf(CALLBACK_OUTPUT, "Politique de mot de passe du domaine : %s\n", domain);

    /* ── Requête : Objet domaine ── */
    const char *filter = "(objectClass=domain)";
    char *attrs[] = {
        "minPwdLength", "maxPwdAge", "minPwdAge", "lockoutThreshold",
        "lockoutDuration", "lockoutObservationWindow", "pwdHistoryLength", "pwdProperties", NULL
    };

    PLDAPMessage msg = NULL;
    if (ldap_search_s(ld, (PCHAR)base_dn, LDAP_SCOPE_SUBTREE, (PCHAR)filter, attrs, 0, &msg) != LDAP_SUCCESS || !msg) {
        BeaconPrintf(CALLBACK_ERROR, "[AD] Requete Password Policy echouee");
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

    /* ── Extraction et conversion des valeurs ── */
    int min_pwd_len = get_int_prop(ld, entry, "minPwdLength", 0);
    long long max_pwd_age = get_large_int_prop(ld, entry, "maxPwdAge");
    long long min_pwd_age = get_large_int_prop(ld, entry, "minPwdAge");
    int lockout_threshold = get_int_prop(ld, entry, "lockoutThreshold", 0);
    long long lockout_duration = get_large_int_prop(ld, entry, "lockoutDuration");
    long long lockout_obs_window = get_large_int_prop(ld, entry, "lockoutObservationWindow");
    int pwd_history_len = get_int_prop(ld, entry, "pwdHistoryLength", 0);
    int pwd_properties = get_int_prop(ld, entry, "pwdProperties", 0);

    int max_days = filetime_to_days(max_pwd_age);
    int min_days = filetime_to_days(min_pwd_age);
    int lockout_mins = filetime_to_minutes(lockout_duration);
    int reset_mins = filetime_to_minutes(lockout_obs_window);

    char pwd_props_str[256] = {0};
    decode_pwd_properties(pwd_properties, pwd_props_str, sizeof(pwd_props_str));

    /* ── Affichage formaté et actionnable pour l'opérateur ── */
    BeaconPrintf(CALLBACK_OUTPUT, "  Longueur minimale       : %d caracteres", min_pwd_len);
    
    if (max_pwd_age == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "  Age maximal             : Illimité (0)");
    else
        BeaconPrintf(CALLBACK_OUTPUT, "  Age maximal (jours)     : %d", max_days);
        
    if (min_pwd_age == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "  Age minimal (jours)     : 0 (Peut changer immédiatement)");
    else
        BeaconPrintf(CALLBACK_OUTPUT, "  Age minimal (jours)     : %d", min_days);

    if (lockout_threshold == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "  Seuil de verrouillage   : Désactivé (0)");
    else
        BeaconPrintf(CALLBACK_OUTPUT, "  Seuil de verrouillage   : %d tentatives", lockout_threshold);

    if (lockout_duration == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "  Duree de verrouillage   : Jusqu'à déverrouillage admin");
    else
        BeaconPrintf(CALLBACK_OUTPUT, "  Duree de verrouillage   : %d minutes", lockout_mins);

    BeaconPrintf(CALLBACK_OUTPUT, "  Fenetre de reinit. (m)  : %d", reset_mins);
    BeaconPrintf(CALLBACK_OUTPUT, "  Historique des MDP      : %d", pwd_history_len);
    BeaconPrintf(CALLBACK_OUTPUT, "  Proprietes              : %s", pwd_props_str);

    ldap_msgfree(msg);
    ldap_unbind_s(ld);
}

#else

BOF_DLL_EXPORT void go(char *args, int args_len) {
    (void)args; (void)args_len;
    BeaconPrintf(CALLBACK_ERROR, "[adpwdpolicy] Mode BOF non supporté — utilisez -t rdll");
}

#endif /* RDLL_MODE */