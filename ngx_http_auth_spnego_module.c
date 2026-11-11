/*
 * Copyright (C) 2009 Michal Kowalski <superflouos{at}gmail[dot]com>
 * Copyright (C) 2012-2013 Sean Timothy Noonan <stnoonan@obsolescence.net>
 * Copyright (C) 2013 Marcello Barnaba <vjt@openssl.it>
 * Copyright (C) 2013 Alexander Pyhalov <alp@sfedu.ru>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_WIN32) && defined(_MSC_VER)
/* nginx defines _OFF_T_DEFINED (for its own 64-bit off_t), which stops the
 * Windows SDK's <sys/types.h> from declaring _off_t. MIT Kerberos for
 * Windows' headers include <sys/stat.h>, which needs it. */
typedef long _off_t;
#endif

#include <gssapi/gssapi.h>
#if !(NGX_HAVE_HEIMDAL_GSSAPI)
/* MIT only, Heimdal declares its GSSAPI extensions in gssapi.h */
#include <gssapi/gssapi_ext.h>
#endif
#include <krb5.h>
#include <stdbool.h>

#if (NGX_HTTP_SSL)
#include <ngx_event_openssl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#endif

/* Both gss_acquire_cred_from() and gss_store_cred_into() must be present to
 * enable constrained-delegation and credential-store features. */
#if defined(NGX_HAVE_GSS_ACQUIRE_CRED_FROM) && defined(NGX_HAVE_GSS_STORE_CRED_INTO)
# define NGX_HAVE_CRED_STORE 1
#endif

#define CCACHE_VARIABLE_NAME "krb5_cc_name"
#define CRED_EXPORT_VARIABLE_NAME "krb5_exported_cred"
#define SESSION_PRINCIPAL_VARIABLE_NAME "krb5_session_principal"
#define AUTH_TYPE_VARIABLE_NAME "krb5_auth_type"
#define RENEWAL_TIME 60
#define BASIC_AUTH_TKT_LIFE 60  /* 1 minute; credential is discarded after password verification */

/* Values for the auth_gss_channel_binding directive. */
#define NGX_HTTP_AUTH_SPNEGO_CB_OFF       0
#define NGX_HTTP_AUTH_SPNEGO_CB_SERVER_EP 1
#define NGX_HTTP_AUTH_SPNEGO_CB_EXPORTER  2

/* Values for the auth_gss_delegation directive (bit-flags). */
#define SPNEGO_DELEG_OFF           0
#define SPNEGO_DELEG_CONSTRAINED   1
#define SPNEGO_DELEG_UNCONSTRAINED 2
#define SPNEGO_DELEG_BOTH          3

/* Heimdal < 8 lacks GSS_C_CHANNEL_BOUND_FLAG, so a successful
 * gss_accept_sec_context() can't be checked for channel binding. */
#ifdef GSS_C_CHANNEL_BOUND_FLAG
#define NGX_HTTP_AUTH_SPNEGO_HAVE_CB_FLAG 1
#endif


#define spnego_error(code)                                                     \
    ret = code;                                                                \
    goto end
#define spnego_debug0(msg)                                                     \
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, msg)
#define spnego_debug1(msg, one)                                                \
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, msg, one)
#define spnego_debug2(msg, one, two)                                           \
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, msg, one, two)
#define spnego_debug3(msg, one, two, three)                                    \
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, msg, one, two,   \
                   three)
#define spnego_log_error(fmt, ...)                                             \
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, fmt, ##__VA_ARGS__)

/* Module handler */
static ngx_int_t ngx_http_auth_spnego_handler(ngx_http_request_t *);

static void *ngx_http_auth_spnego_create_loc_conf(ngx_conf_t *);
static char *ngx_http_auth_spnego_merge_loc_conf(ngx_conf_t *, void *, void *);
static ngx_int_t ngx_http_auth_spnego_init(ngx_conf_t *);

#if (NGX_PCRE)
static char *ngx_conf_set_regex_array_slot(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf);
#endif
ngx_int_t ngx_http_auth_spnego_set_bogus_authorization(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_spnego_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_spnego_add_www_authenticate(ngx_http_request_t *r,
                                                            ngx_str_t *value,
                                                            ngx_uint_t hash);

static int
ngx_http_auth_spnego_hex_decode(const u_char *hex, uint8_t *out, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        u_char hi = hex[2 * i], lo = hex[2 * i + 1];
        if (!((hi >= '0' && hi <= '9') || (hi >= 'a' && hi <= 'f')
              || (hi >= 'A' && hi <= 'F'))
            || !((lo >= '0' && lo <= '9') || (lo >= 'a' && lo <= 'f')
                 || (lo >= 'A' && lo <= 'F')))
        {
            return NGX_ERROR;
        }
        hi = (hi >= 'a') ? (hi - 'a' + 10) :
             (hi >= 'A') ? (hi - 'A' + 10) : (hi - '0');
        lo = (lo >= 'a') ? (lo - 'a' + 10) :
             (lo >= 'A') ? (lo - 'A' + 10) : (lo - '0');
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return NGX_OK;
}


static const char *get_gss_error(ngx_pool_t *p, OM_uint32 major_status,
                                  OM_uint32 minor_status, char *prefix) {
    OM_uint32 maj_stat, min_stat;
    OM_uint32 msg_ctx;
    gss_buffer_desc status_string;
    char buf[1024];
    u_char *bp;
    size_t len;
    ngx_str_t str;
    /* Bounded write with explicit NUL: a too-long prefix is truncated
     * instead of leaving buf without a terminator. */
    bp = ngx_snprintf((u_char *)buf, sizeof(buf) - 1, "%s: ", prefix);
    *bp = '\0';
    len = (size_t)(bp - (u_char *)buf);
    msg_ctx = 0;
    do {
        /* gss_display_status() may leave status_string untouched on
         * failure; don't read or release an uninitialized buffer. */
        status_string.length = 0;
        status_string.value = NULL;
        maj_stat = gss_display_status(&min_stat, major_status, GSS_C_GSS_CODE,
                                      GSS_C_NO_OID, &msg_ctx, &status_string);
        if (GSS_ERROR(maj_stat))
            break;
        if (sizeof(buf) > len + status_string.length + 2) {
            ngx_snprintf((u_char *)buf + len, sizeof(buf) - len, "%*s:%Z",
                         (size_t)status_string.length, status_string.value);
            len += (status_string.length + 1);
        }
        gss_release_buffer(&min_stat, &status_string);
    } while (msg_ctx != 0);
    msg_ctx = 0;
    do {
        status_string.length = 0;
        status_string.value = NULL;
        maj_stat = gss_display_status(&min_stat, minor_status, GSS_C_MECH_CODE,
                                      GSS_C_NO_OID, &msg_ctx, &status_string);
        if (GSS_ERROR(maj_stat))
            break;
        if (sizeof(buf) > len + status_string.length + 2) {
            ngx_snprintf((u_char *)buf + len, sizeof(buf) - len, "%*s:%Z",
                         (size_t)status_string.length, status_string.value);
            len += (status_string.length + 1);
        }
        gss_release_buffer(&min_stat, &status_string);
    } while (msg_ctx != 0);

    str.len = len + 1; /* includes '\0' */
    str.data = (u_char *)buf;
    return (char *)(ngx_pstrdup(p, &str));
}

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;


/* per request */
typedef struct {
    ngx_str_t token;             /* decoded Negotiate token */
    ngx_int_t head;              /* non-zero flag if headers set */
    ngx_int_t ret;               /* current return code */
    ngx_str_t token_out_b64;     /* base64 encoded output token */
    ngx_str_t session_cookie_val;  /* encrypted value to emit as Set-Cookie */
    ngx_str_t session_cookie_name; /* cookie name (from alcf, no copy) */
    ngx_int_t session_expiry;      /* Max-Age seconds for Set-Cookie */
    ngx_str_t user;              /* authenticated username */
    ngx_str_t authorization_set; /* copy of the header value after login */
    ngx_str_t ccache;            /* delegated cache name, kept across refusals */
    ngx_uint_t redirected;       /* the saved login reached another access check */
    ngx_uint_t uri_changes;      /* r->uri_changes when saved or last reused */
    ngx_table_elt_t *challenge;  /* challenge kept across redirects */
    ngx_str_t challenge_value;   /* detects a reused header list entry */
    struct ngx_http_auth_spnego_loc_conf_s *alcf; /* NULL discards the login */
} ngx_http_auth_spnego_ctx_t;

typedef struct ngx_http_auth_spnego_loc_conf_s {
    ngx_flag_t protect;               /* auth_gss on/off */
    ngx_str_t realm;                  /* Kerberos realm */
    ngx_str_t keytab;                 /* keytab path (config value) */
    char *keytab_prefix_path;         /* "FILE:"-prefixed path, built at config time */
    char *keytab_path;                /* plain path: keytab_prefix_path + 5 */
    ngx_str_t srvcname;               /* service principal name override */
    char *service_principal;          /* fully-qualified service principal */
    ngx_flag_t fqun;                  /* include @realm in $remote_user */
    ngx_flag_t force_realm;           /* strip/replace principal's realm */
    ngx_flag_t allow_basic;           /* allow Basic auth fallback */
    ngx_array_t *auth_princs;         /* authorized principals */
#if (NGX_PCRE)
    ngx_array_t *auth_princs_regex;   /* regexes matching authorized principals */
#endif
    ngx_flag_t map_to_local;          /* map principal to local name via gss_localname() */
    ngx_uint_t delegation;            /* SPNEGO_DELEG_* */
#ifdef NGX_HAVE_CRED_STORE
    ngx_str_t deleg_ccache_dir;       /* dir for NFS-backed delegation ccaches */
    gss_cred_id_t constrained_creds;  /* service TGT for S4U2Proxy */
#endif
    ngx_uint_t channel_binding;       /* NGX_HTTP_AUTH_SPNEGO_CB_* */
    /* session cookie (requires OpenSSL / NGX_HTTP_SSL) */
    ngx_str_t session_key;            /* 64-char hex AES-256-GCM key (inline) */
    ngx_str_t session_key_file;       /* path to file containing 64-char hex key */
    uint8_t session_key_bytes[32];    /* decoded master key */
    uint8_t session_enc_key[32];      /* AES-256-GCM subkey derived from session_key_bytes */
    uint8_t session_mac_key[32];      /* HMAC-SHA256 subkey derived from session_key_bytes */
    u_char *session_aad;              /* "cookie_name\0service_principal" — see merge_loc_conf */
    size_t  session_aad_len;
#if (NGX_HTTP_SSL)
    EVP_CIPHER *session_cipher;       /* cached AES-256-GCM-SIV (NULL if !session_key_loaded) */
    EVP_MAC    *session_mac;          /* cached HMAC (NULL if !session_key_loaded) */
#endif
    ngx_str_t session_cookie_name;    /* cookie name, default "gss_session" */
    ngx_str_t session_cookie_attrs;   /* Set-Cookie attributes appended after Max-Age */
    ngx_int_t session_expiry;         /* cookie Max-Age in seconds; 0 = disabled */
    ngx_uint_t session_key_loaded;    /* 1 when enc/mac subkeys are ready */
} ngx_http_auth_spnego_loc_conf_t;

static void ngx_http_auth_spnego_strip_realm(ngx_http_request_t *,
                                             ngx_http_auth_spnego_loc_conf_t *);
static bool ngx_http_auth_spnego_same_authorization(ngx_http_request_t *,
                                                    ngx_http_auth_spnego_ctx_t *);
static bool ngx_http_auth_spnego_same_auth(ngx_http_auth_spnego_ctx_t *,
                                          ngx_http_auth_spnego_loc_conf_t *);
static ngx_http_auth_spnego_ctx_t *
ngx_http_auth_spnego_get_ctx(ngx_http_request_t *);
static ngx_http_auth_spnego_ctx_t *
ngx_http_auth_spnego_saved_ccache(ngx_http_request_t *);
static bool ngx_spnego_authorized_principal(ngx_http_request_t *, ngx_str_t *,
                                            ngx_http_auth_spnego_loc_conf_t *);
static ngx_int_t ngx_http_auth_spnego_exported_cred_variable(ngx_http_request_t *,
                                                              ngx_http_variable_value_t *,
                                                              uintptr_t);

#define SPNEGO_NGX_CONF_FLAGS                                                  \
    NGX_HTTP_MAIN_CONF                                                         \
    | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_FLAG

static const ngx_conf_enum_t ngx_http_auth_spnego_cb[] = {
    { ngx_string("off"),              NGX_HTTP_AUTH_SPNEGO_CB_OFF },
#if (NGX_HTTP_SSL)
    { ngx_string("server-end-point"), NGX_HTTP_AUTH_SPNEGO_CB_SERVER_EP },
    { ngx_string("exporter"),         NGX_HTTP_AUTH_SPNEGO_CB_EXPORTER },
#endif
    { ngx_null_string, 0 }
};

static const ngx_conf_enum_t ngx_http_auth_spnego_delegation_enum[] = {
    { ngx_string("off"),           SPNEGO_DELEG_OFF },
    { ngx_string("constrained"),   SPNEGO_DELEG_CONSTRAINED },
    { ngx_string("unconstrained"), SPNEGO_DELEG_UNCONSTRAINED },
    { ngx_string("both"),          SPNEGO_DELEG_BOTH },
    { ngx_null_string, 0 }
};

/* Module Directives */
static ngx_command_t ngx_http_auth_spnego_commands[] = {
    {ngx_string("auth_gss"), SPNEGO_NGX_CONF_FLAGS, ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, protect), NULL},

    {ngx_string("auth_gss_realm"), SPNEGO_NGX_CONF_FLAGS, ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http_auth_spnego_loc_conf_t, realm),
     NULL},

    {ngx_string("auth_gss_keytab"), SPNEGO_NGX_CONF_FLAGS,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, keytab), NULL},

    {ngx_string("auth_gss_service_name"), SPNEGO_NGX_CONF_FLAGS,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, srvcname), NULL},

    {ngx_string("auth_gss_format_full"), SPNEGO_NGX_CONF_FLAGS,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, fqun), NULL},

    {ngx_string("auth_gss_force_realm"), SPNEGO_NGX_CONF_FLAGS,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, force_realm), NULL},

    {ngx_string("auth_gss_allow_basic_fallback"), SPNEGO_NGX_CONF_FLAGS,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, allow_basic), NULL},

    {ngx_string("auth_gss_authorized_principal"),
     SPNEGO_NGX_CONF_FLAGS | NGX_CONF_1MORE, ngx_conf_set_str_array_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, auth_princs), NULL},
#if (NGX_PCRE)
    {ngx_string("auth_gss_authorized_principal_regex"),
     SPNEGO_NGX_CONF_FLAGS | NGX_CONF_1MORE, ngx_conf_set_regex_array_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, auth_princs_regex), NULL},
#endif
    {ngx_string("auth_gss_map_to_local"), SPNEGO_NGX_CONF_FLAGS,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, map_to_local), NULL},

    {ngx_string("auth_gss_delegation"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
         | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_enum_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, delegation),
     (void *) &ngx_http_auth_spnego_delegation_enum},

    {ngx_string("auth_gss_channel_binding"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
         | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_enum_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, channel_binding),
     (void *) &ngx_http_auth_spnego_cb},

#ifdef NGX_HAVE_CRED_STORE
    {ngx_string("auth_gss_deleg_ccache_dir"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, deleg_ccache_dir), NULL},
#endif

    {ngx_string("auth_gss_session_key"), SPNEGO_NGX_CONF_FLAGS,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, session_key), NULL},

    {ngx_string("auth_gss_session_key_file"), SPNEGO_NGX_CONF_FLAGS,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, session_key_file), NULL},

    {ngx_string("auth_gss_session_cookie_name"), SPNEGO_NGX_CONF_FLAGS,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, session_cookie_name), NULL},

    {ngx_string("auth_gss_session_cookie_attrs"), SPNEGO_NGX_CONF_FLAGS,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, session_cookie_attrs), NULL},

    {ngx_string("auth_gss_session_expiry"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_spnego_loc_conf_t, session_expiry), NULL},

    ngx_null_command};

/* Module Context */
static ngx_http_module_t ngx_http_auth_spnego_module_ctx = {
    NULL,                      /* preconf */
    ngx_http_auth_spnego_init, /* postconf */
    NULL,                      /* create main conf (defaults) */
    NULL,                      /* init main conf (what's in nginx.conf) */
    NULL,                      /* create server conf */
    NULL,                      /* merge with main */

    ngx_http_auth_spnego_create_loc_conf, /* create location conf */
    ngx_http_auth_spnego_merge_loc_conf,  /* merge with server */
};

/* Module Definition */
ngx_module_t ngx_http_auth_spnego_module = {
    /* ngx_uint_t ctx_index, index, spare{0-3}, version; */
    NGX_MODULE_V1,                    /* 0, 0, 0, 0, 0, 0, 1 */
    &ngx_http_auth_spnego_module_ctx, /* void *ctx */
    ngx_http_auth_spnego_commands,    /* ngx_command_t *commands */
    NGX_HTTP_MODULE,                  /* ngx_uint_t type = 0x50545448 */
    NULL,                  /* ngx_int_t (*init_master)(ngx_log_t *log) */
    NULL,                  /* ngx_int_t (*init_module)(ngx_cycle_t *cycle) */
    NULL,                  /* ngx_int_t (*init_process)(ngx_cycle_t *cycle) */
    NULL,                  /* ngx_int_t (*init_thread)(ngx_cycle_t *cycle) */
    NULL,                  /* void (*exit_thread)(ngx_cycle_t *cycle) */
    NULL,                  /* void (*exit_process)(ngx_cycle_t *cycle) */
    NULL,                  /* void (*exit_master)(ngx_cycle_t *cycle) */
    NGX_MODULE_V1_PADDING, /* 0, 0, 0, 0, 0, 0, 0, 0 */
    /* uintptr_t spare_hook{0-7}; */
};

#if (NGX_PCRE)
static char *ngx_conf_set_regex_array_slot(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf) {
    char *p = conf;
    u_char errstr[NGX_MAX_CONF_ERRSTR];
    ngx_str_t *value;
    ngx_regex_elt_t *re;
    ngx_regex_compile_t rc;
    ngx_array_t **a;
    ngx_conf_post_t *post;

    a = (ngx_array_t **)(p + cmd->offset);

    if (*a == NGX_CONF_UNSET_PTR) {
        *a = ngx_array_create(cf->pool, 4, sizeof(ngx_regex_elt_t));
        if (*a == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    re = ngx_array_push(*a);
    if (re == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = value[1];
    rc.pool = cf->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    re->regex = rc.regex;
    re->name = value[1].data;

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, re);
    }

    return NGX_CONF_OK;
}
#endif

static void *ngx_http_auth_spnego_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_auth_spnego_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_spnego_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->protect = NGX_CONF_UNSET;
    conf->fqun = NGX_CONF_UNSET;
    conf->force_realm = NGX_CONF_UNSET;
    conf->allow_basic = NGX_CONF_UNSET;
    conf->auth_princs = NGX_CONF_UNSET_PTR;
#if (NGX_PCRE)
    conf->auth_princs_regex = NGX_CONF_UNSET_PTR;
#endif
    conf->map_to_local = NGX_CONF_UNSET;
    conf->delegation = NGX_CONF_UNSET_UINT;
#ifdef NGX_HAVE_CRED_STORE
    conf->constrained_creds = GSS_C_NO_CREDENTIAL;
#endif
    conf->channel_binding = NGX_CONF_UNSET_UINT;
    conf->session_expiry = NGX_CONF_UNSET;

    return conf;
}

#if (NGX_HTTP_SSL)
static void
ngx_http_auth_spnego_release_session_objects(void *data)
{
    ngx_http_auth_spnego_loc_conf_t *alcf = data;
    EVP_CIPHER_free(alcf->session_cipher);
    EVP_MAC_free(alcf->session_mac);
    /* Wipe key material before the pool reclaims the storage, so stale
     * key bytes don't linger in freed pool memory available for reuse. */
    ngx_explicit_memzero(alcf->session_key_bytes, sizeof(alcf->session_key_bytes));
    ngx_explicit_memzero(alcf->session_enc_key,   sizeof(alcf->session_enc_key));
    ngx_explicit_memzero(alcf->session_mac_key,   sizeof(alcf->session_mac_key));
    ngx_explicit_memzero(alcf->session_key.data, alcf->session_key.len);
}
#endif

static char *ngx_http_auth_spnego_merge_loc_conf(ngx_conf_t *cf, void *parent,
                                                 void *child) {
    ngx_http_auth_spnego_loc_conf_t *prev = parent;
    ngx_http_auth_spnego_loc_conf_t *conf = child;

    /* "off" by default */
    ngx_conf_merge_off_value(conf->protect, prev->protect, 0);

    ngx_conf_merge_str_value(conf->realm, prev->realm, "");
    ngx_conf_merge_str_value(conf->keytab, prev->keytab, "/etc/krb5.keytab");

    conf->keytab_prefix_path = ngx_pnalloc(cf->pool,
                                            sizeof("FILE:") + conf->keytab.len);
    if (conf->keytab_prefix_path == NULL)
        return NGX_CONF_ERROR;
    ngx_snprintf((u_char *)conf->keytab_prefix_path,
                 sizeof("FILE:") + conf->keytab.len,
                 "FILE:%V%Z", &conf->keytab);
    conf->keytab_path = conf->keytab_prefix_path + (sizeof("FILE:") - 1);

#ifndef NGX_HAVE_GSS_ACQUIRE_CRED_FROM
    if (conf->keytab.len > 0
        && ngx_strcmp(conf->keytab.data, "/etc/krb5.keytab") != 0)
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "auth_gss_keytab \"%V\" cannot be honored: this "
                           "build lacks gss_acquire_cred_from(); the default "
                           "acceptor credential (KRB5_KTNAME or "
                           "/etc/krb5.keytab) will be used instead",
                           &conf->keytab);
    }
#endif

    ngx_conf_merge_str_value(conf->srvcname, prev->srvcname, "");

    ngx_conf_merge_off_value(conf->fqun, prev->fqun, 0);
    ngx_conf_merge_off_value(conf->force_realm, prev->force_realm, 0);
    ngx_conf_merge_off_value(conf->allow_basic, prev->allow_basic, 1);

    if (!conf->realm.len) {
        krb5_context kctx;
        char *defrealm = NULL;

        if (krb5_init_context(&kctx) != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_spnego: krb5_init_context() failed");
            return NGX_CONF_ERROR;
        }
        if (krb5_get_default_realm(kctx, &defrealm) == 0) {
            size_t rlen = ngx_strlen(defrealm);
            u_char *rdata = ngx_palloc(cf->pool, rlen + 1);
            if (rdata == NULL) {
                krb5_free_default_realm(kctx, defrealm);
                krb5_free_context(kctx);
                return NGX_CONF_ERROR;
            }
            ngx_cpystrn(rdata, (u_char *)defrealm, rlen + 1);
            conf->realm.data = rdata;
            conf->realm.len = rlen;
            krb5_free_default_realm(kctx, defrealm);
        }
        krb5_free_context(kctx);
    }

    if (conf->protect && !conf->realm.len && conf->allow_basic) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gss_allow_basic_fallback requires "
                           "auth_gss_realm or a default_realm in krb5.conf");
        return NGX_CONF_ERROR;
    }

    if (conf->protect && (conf->srvcname.len || conf->allow_basic)) {
        ngx_http_core_srv_conf_t *cscf =
            ((ngx_http_conf_ctx_t *)cf->ctx)
                ->srv_conf[ngx_http_core_module.ctx_index];
        ngx_str_t host = cscf->server_name;
        ngx_str_t svc = conf->srvcname;
        bool has_slash;
        size_t len;

        if (!svc.len) {
            ngx_str_set(&svc, "HTTP");
        }

        has_slash = ngx_strchr(svc.data, '/') != NULL;

        if (!has_slash && host.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_spnego: no server_name configured; set "
                               "auth_gss_service_name to a full "
                               "service/hostname principal");
            return NGX_CONF_ERROR;
        } else if (!has_slash && host.data[0] == '*') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_spnego: server_name \"%V\" is a "
                               "wildcard; set auth_gss_service_name to a "
                               "full service/hostname principal", &host);
            return NGX_CONF_ERROR;
        }

        len = svc.len
              + (has_slash ? 0 : 1 + host.len)
              + (conf->realm.len ? conf->realm.len + 2 : 1);
        conf->service_principal = ngx_palloc(cf->pool, len);
        if (conf->service_principal == NULL)
            return NGX_CONF_ERROR;

        if (has_slash && conf->realm.len)
            ngx_snprintf((u_char *)conf->service_principal, len,
                         "%V@%V%Z", &svc, &conf->realm);
        else if (has_slash)
            ngx_snprintf((u_char *)conf->service_principal, len,
                         "%V%Z", &svc);
        else if (conf->realm.len)
            ngx_snprintf((u_char *)conf->service_principal, len,
                         "%V/%V@%V%Z", &svc, &host, &conf->realm);
        else
            ngx_snprintf((u_char *)conf->service_principal, len,
                         "%V/%V%Z", &svc, &host);
    }

    ngx_conf_merge_ptr_value(conf->auth_princs, prev->auth_princs,
                             NGX_CONF_UNSET_PTR);

#if (NGX_PCRE)
    ngx_conf_merge_ptr_value(conf->auth_princs_regex, prev->auth_princs_regex,
                             NGX_CONF_UNSET_PTR);
#endif

    ngx_conf_merge_off_value(conf->map_to_local, prev->map_to_local, 0);

    ngx_conf_merge_uint_value(conf->delegation, prev->delegation,
                              SPNEGO_DELEG_OFF);
#ifdef NGX_HAVE_CRED_STORE
    ngx_conf_merge_str_value(conf->deleg_ccache_dir, prev->deleg_ccache_dir, "");

    if (conf->delegation != SPNEGO_DELEG_OFF
        && conf->deleg_ccache_dir.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gss_delegation requires "
                           "auth_gss_deleg_ccache_dir to be set");
        return NGX_CONF_ERROR;
    }

    if (conf->deleg_ccache_dir.len > 0) {
        ngx_file_info_t fi;
        char *dir = (char *)conf->deleg_ccache_dir.data;
        if (ngx_file_info(conf->deleg_ccache_dir.data, &fi) == NGX_FILE_ERROR
            || !ngx_is_dir(&fi))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_gss_deleg_ccache_dir \"%V\" does not "
                               "exist or is not a directory",
                               &conf->deleg_ccache_dir);
            return NGX_CONF_ERROR;
        }
        if (access(dir, W_OK | X_OK) != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_gss_deleg_ccache_dir \"%V\" is not "
                               "writable", &conf->deleg_ccache_dir);
            return NGX_CONF_ERROR;
        }
    }
#else
    if (conf->delegation != SPNEGO_DELEG_OFF) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gss_delegation requires gss_acquire_cred_from() "
                           "and gss_store_cred_into() which are not available");
        return NGX_CONF_ERROR;
    }
#endif


    ngx_conf_merge_uint_value(conf->channel_binding,
                              prev->channel_binding,
                              NGX_HTTP_AUTH_SPNEGO_CB_OFF);

#ifndef NGX_HTTP_AUTH_SPNEGO_HAVE_CB_FLAG
    if (conf->channel_binding != NGX_HTTP_AUTH_SPNEGO_CB_OFF) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gss_channel_binding is not supported: "
                           "the GSSAPI library lacks GSS_C_CHANNEL_BOUND_FLAG");
        return NGX_CONF_ERROR;
    }
#endif
    ngx_conf_merge_str_value(conf->session_key, prev->session_key, "");
    ngx_conf_merge_str_value(conf->session_key_file, prev->session_key_file, "");
    ngx_conf_merge_str_value(conf->session_cookie_name, prev->session_cookie_name,
                             "gss_session");
    ngx_conf_merge_str_value(conf->session_cookie_attrs, prev->session_cookie_attrs,
                             "HttpOnly; Path=/; Secure; SameSite=Lax");
    ngx_conf_merge_value(conf->session_expiry, prev->session_expiry, 0);

    if (conf->session_key.len > 0 && conf->session_key_file.len > 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_gss_session_key and auth_gss_session_key_file "
                           "are mutually exclusive");
        return NGX_CONF_ERROR;
    }

    {
        int have_key = 0;

        if (conf->session_key_file.len > 0) {
            u_char          *path;
            ngx_fd_t         fd;
            ssize_t          n;
            char             buf[66]; /* 64 hex + optional newline + NUL */
            size_t           hex_len;
            ngx_file_info_t  fi;

            path = ngx_pnalloc(cf->pool, conf->session_key_file.len + 1);
            if (path == NULL)
                return NGX_CONF_ERROR;
            ngx_memcpy(path, conf->session_key_file.data,
                       conf->session_key_file.len);
            path[conf->session_key_file.len] = '\0';

            fd = ngx_open_file(path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
            if (fd == NGX_INVALID_FILE) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                   "auth_gss_session_key_file: "
                                   ngx_open_file_n " \"%s\" failed", path);
                return NGX_CONF_ERROR;
            }

            if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                   "auth_gss_session_key_file: "
                                   ngx_fd_info_n " \"%s\" failed", path);
                ngx_close_file(fd);
                return NGX_CONF_ERROR;
            }

            /* Always 0 on Windows, where POSIX permissions don't apply */
            if (ngx_file_access(&fi) & 077) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "auth_gss_session_key_file \"%s\": "
                                   "mode allows group/other access", path);
                ngx_close_file(fd);
                return NGX_CONF_ERROR;
            }

            n = ngx_read_fd(fd, buf, sizeof(buf) - 1);
            ngx_close_file(fd);

            if (n == -1) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                   "auth_gss_session_key_file: "
                                   ngx_read_fd_n " \"%s\" failed", path);
                return NGX_CONF_ERROR;
            }

            buf[n] = '\0';
            hex_len = (size_t)n;

            while (hex_len > 0
                   && (buf[hex_len - 1] == '\n' || buf[hex_len - 1] == '\r'))
                hex_len--;

            if (hex_len != 64
                || ngx_http_auth_spnego_hex_decode((u_char *)buf,
                                                   conf->session_key_bytes,
                                                   32) != NGX_OK)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "auth_gss_session_key_file \"%s\" must "
                                   "contain exactly 64 hex characters",
                                   path);
                return NGX_CONF_ERROR;
            }

            have_key = 1;

        } else if (conf->session_key.len == 64) {
            if (ngx_http_auth_spnego_hex_decode(conf->session_key.data,
                                                conf->session_key_bytes,
                                                32) != NGX_OK)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "auth_gss_session_key contains "
                                   "non-hex characters");
                return NGX_CONF_ERROR;
            }
            have_key = 1;

        } else if (conf->session_key.len > 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_gss_session_key must be exactly 64 hex "
                               "characters (32-byte AES-256 key), got %uz",
                               conf->session_key.len);
            return NGX_CONF_ERROR;
        }

        if (have_key) {
#if (NGX_HTTP_SSL)
            static const char enc_info[] = "spnego-session-enc";
            static const char mac_info[] = "spnego-session-mac";
            EVP_KDF     *kdf;
            EVP_KDF_CTX *kctx;
            OSSL_PARAM   params[4];

            kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
            if (kdf == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "auth_spnego: HKDF unavailable");
                return NGX_CONF_ERROR;
            }

            params[0] = OSSL_PARAM_construct_utf8_string(
                            OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
            params[1] = OSSL_PARAM_construct_octet_string(
                            OSSL_KDF_PARAM_KEY,
                            conf->session_key_bytes, 32);
            params[2] = OSSL_PARAM_construct_octet_string(
                            OSSL_KDF_PARAM_INFO,
                            (void *)enc_info, sizeof(enc_info) - 1);
            params[3] = OSSL_PARAM_construct_end();

            kctx = EVP_KDF_CTX_new(kdf);
            if (kctx == NULL
                || EVP_KDF_derive(kctx, conf->session_enc_key, 32,
                                  params) != 1)
            {
                EVP_KDF_CTX_free(kctx);
                EVP_KDF_free(kdf);
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "auth_spnego: HKDF enc key derivation failed");
                return NGX_CONF_ERROR;
            }
            EVP_KDF_CTX_free(kctx);

            params[2] = OSSL_PARAM_construct_octet_string(
                            OSSL_KDF_PARAM_INFO,
                            (void *)mac_info, sizeof(mac_info) - 1);

            kctx = EVP_KDF_CTX_new(kdf);
            if (kctx == NULL
                || EVP_KDF_derive(kctx, conf->session_mac_key, 32,
                                  params) != 1)
            {
                EVP_KDF_CTX_free(kctx);
                EVP_KDF_free(kdf);
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "auth_spnego: HKDF mac key derivation failed");
                return NGX_CONF_ERROR;
            }
            EVP_KDF_CTX_free(kctx);
            EVP_KDF_free(kdf);
            conf->session_key_loaded = 1;

            conf->session_cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM-SIV", NULL);
            conf->session_mac    = EVP_MAC_fetch(NULL, "HMAC", NULL);
            if (conf->session_cipher == NULL || conf->session_mac == NULL) {
                if (conf->session_cipher == NULL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "auth_spnego: session cookies require "
                                       "the AES-256-GCM-SIV cipher, which needs "
                                       "OpenSSL 3.2 or later");
                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "auth_spnego: session cookies require "
                                       "HMAC, which OpenSSL does not provide");
                }
                EVP_CIPHER_free(conf->session_cipher);
                EVP_MAC_free(conf->session_mac);
                return NGX_CONF_ERROR;
            }

            ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(cf->pool, 0);
            if (cln == NULL)
                return NGX_CONF_ERROR;
            cln->handler = ngx_http_auth_spnego_release_session_objects;
            cln->data    = conf;
#endif

            /* AAD = cookie_name || '\0' || service_principal.
             *
             * Binds each cookie cryptographically to the specific service
             * that minted it.  The service principal (HTTP/hostname@REALM)
             * uniquely identifies the SPNEGO service, so a master key
             * accidentally shared between unrelated services won't produce
             * interchangeable cookies — AEAD verification fails on the
             * mismatched AAD before any plaintext is exposed.  Cluster
             * behavior is preserved: load-balanced replicas of the same
             * service share the same SPN, so AAD matches and cookies remain
             * portable across nodes.
             *
             * service_principal is NULL when auth_gss_allow_basic_fallback
             * is off and no auth_gss_service_name is set (the GSS acceptor
             * then matches any keytab entry via GSS_C_NO_NAME).  Cookies
             * need a concrete service identity to bind to, so require
             * auth_gss_service_name to be set in that case. */
            if (conf->service_principal == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "auth_gss_session_key requires "
                                   "auth_gss_service_name to be set");
                return NGX_CONF_ERROR;
            }

            {
                size_t spn_len = ngx_strlen(conf->service_principal);
                u_char *p;

                conf->session_aad_len = conf->session_cookie_name.len
                                        + 1 + spn_len;
                conf->session_aad = ngx_pnalloc(cf->pool,
                                                conf->session_aad_len);
                if (conf->session_aad == NULL)
                    return NGX_CONF_ERROR;

                p = ngx_cpymem(conf->session_aad,
                               conf->session_cookie_name.data,
                               conf->session_cookie_name.len);
                *p++ = '\0';
                ngx_memcpy(p, conf->service_principal, spn_len);
            }
        }
    }

#if (NGX_DEBUG)
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "auth_spnego: protect = %i",
                       conf->protect);
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "auth_spnego: realm@0x%p = %s",
                       conf->realm.data, conf->realm.data);
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "auth_spnego: keytab@0x%p = %s",
                       conf->keytab.data, conf->keytab.data);
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "auth_spnego: srvcname@0x%p = %s",
                       conf->srvcname.data, conf->srvcname.data);
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "auth_spnego: fqun = %i",
                       conf->fqun);
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "auth_spnego: allow_basic = %i",
                       conf->allow_basic);
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "auth_spnego: force_realm = %i",
                       conf->force_realm);

    if (NGX_CONF_UNSET_PTR != conf->auth_princs) {
        size_t ii = 0;
        ngx_str_t *auth_princs = conf->auth_princs->elts;
        for (; ii < conf->auth_princs->nelts; ++ii) {
            ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
                               "auth_spnego: auth_princs = %.*s",
                               auth_princs[ii].len, auth_princs[ii].data);
        }
    }

#if (NGX_PCRE)
    if (NGX_CONF_UNSET_PTR != conf->auth_princs_regex) {
        size_t ii = 0;
        ngx_regex_elt_t *auth_princs_regex = conf->auth_princs_regex->elts;
        for (; ii < conf->auth_princs_regex->nelts; ++ii) {
            ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
                               "auth_spnego: auth_princs_regex = %.*s",
                               ngx_strlen(auth_princs_regex[ii].name),
                               auth_princs_regex[ii].name);
        }
    }
#endif

    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "auth_spnego: map_to_local = %i",
                       conf->map_to_local);

    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
                       "auth_spnego: delegation = %ui",
                       conf->delegation);
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
                       "auth_spnego: channel_binding = %ui",
                       conf->channel_binding);
#endif

    return NGX_CONF_OK;
}


/* nginx has stored values only for variables indexed by the configuration. */
static ngx_http_variable_value_t *
ngx_http_auth_spnego_indexed_variable(ngx_http_request_t *r, ngx_str_t *name) {
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_variable_t *var;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    var = ngx_hash_find(&cmcf->variables_hash,
                        ngx_hash_key(name->data, name->len),
                        name->data, name->len);
    if (var != NULL && (var->flags & NGX_HTTP_VAR_INDEXED)) {
        return &r->variables[var->index];
    }
    return NULL;
}


/* A public subrequest keeps credentials even if its parent refuses them. */
static ngx_http_auth_spnego_loc_conf_t *
ngx_http_auth_spnego_ccache_conf(ngx_http_request_t *r) {
    ngx_http_auth_spnego_loc_conf_t *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_spnego_module);
    if (alcf->protect) {
        alcf = ngx_http_get_module_loc_conf(r->main, ngx_http_auth_spnego_module);
    }
    return alcf;
}


/* Subrequests share the main request's variables. Before a destination's
 * access check, its settings and principal list decide whether it may read
 * the saved credentials. A filter can also clear the context, without a
 * redirect: uri_changes distinguishes that case and keeps the direct result. */
static ngx_http_auth_spnego_ctx_t *
ngx_http_auth_spnego_ccache_ctx(ngx_http_request_t *r) {
    ngx_http_auth_spnego_ctx_t *ctx;
    ngx_http_auth_spnego_loc_conf_t *alcf;

    ctx = ngx_http_get_module_ctx(r->main, ngx_http_auth_spnego_module);
    alcf = ngx_http_auth_spnego_ccache_conf(r);
    if (!alcf->protect) {
        return ngx_http_auth_spnego_saved_ccache(r);
    }
    if (ctx != NULL) {
        if (!ctx->redirected || ctx->ret == NGX_OK) {
            return ctx;
        }
        return NULL;
    }

    ctx = ngx_http_auth_spnego_saved_ccache(r);
    if (ctx == NULL) {
        return NULL;
    }
    if (ctx->uri_changes == r->main->uri_changes) {
        if (!ctx->redirected || ctx->ret == NGX_OK) {
            return ctx;
        }
        return NULL;
    }
    if (!ngx_http_auth_spnego_same_authorization(r->main, ctx)
        || !ngx_http_auth_spnego_same_auth(ctx, alcf)
        || !ngx_spnego_authorized_principal(r->main, &ctx->user, alcf)) {
        return NULL;
    }
    return ctx;
}


/* Indexed results stay invalid so reads after a redirect recheck access.
 * The default no_cacheable value preserves auth_request_set assignments. */
static ngx_int_t ngx_http_auth_spnego_get_handler(ngx_http_request_t *r,
                                                  ngx_http_variable_value_t *v,
                                                  uintptr_t data) {
    ngx_str_t name = ngx_string(CCACHE_VARIABLE_NAME);
    ngx_http_variable_value_t *stored;
    ngx_http_auth_spnego_ctx_t *ctx;
    ngx_http_core_main_conf_t *cmcf;

    stored = ngx_http_auth_spnego_indexed_variable(r, &name);
    ctx = ngx_http_get_module_ctx(r->main, ngx_http_auth_spnego_module);
    if (v != stored) {
        *v = ngx_http_variable_null_value;
        if (ctx != NULL && !ctx->redirected) {
            return NGX_OK;
        }
        if (ctx == NULL && (ngx_http_auth_spnego_saved_ccache(r) == NULL)) {
            return NGX_OK;
        }
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    /* Server rewrite precedes destination selection, so access cannot be
     * checked yet. ngx_http_init_phase_handlers() sets location_rewrite_index
     * even when no location rewrite handlers are registered. */
    if (r->phase_handler < (ngx_int_t) cmcf->phase_engine.location_rewrite_index) {
        ctx = ngx_http_auth_spnego_saved_ccache(r);
    } else {
        ctx = ngx_http_auth_spnego_ccache_ctx(r);
    }
    *v = ngx_http_variable_null_value;
    if (ctx != NULL && ctx->ccache.data != NULL) {
        v->len = ctx->ccache.len;
        v->data = ctx->ccache.data;
    } else if (v != stored) {
        /* nginx returns a cached not_found from indexed storage without
         * calling the getter again, which would defeat the recheck below. */
        v->not_found = 1;
    }
    if (v == stored) {
        /* Indexed reads must call the getter again after a redirect. */
        v->valid = 0;
    }
    return NGX_OK;
}


/* The other module variables hold a plain value for the current request,
 * stored by ngx_http_auth_spnego_set_variable(). */
static ngx_int_t ngx_http_auth_spnego_get_plain_handler(ngx_http_request_t *r,
                                                        ngx_http_variable_value_t *v,
                                                        uintptr_t data) {
    /* ngx_http_auth_spnego_set_variable() fills these in once the variable
     * has a value; until then, mark it as not found rather than leaving a
     * zeroed (len=0, valid=0, not_found=0) value. */
    v->not_found = 1;

    return NGX_OK;
}


/* Keep the module's variable with its login so a refusal cannot destroy the
 * name needed by a later accepting destination. Invalidate indexed storage
 * so a redirect cannot bypass the getter's checks. */
static ngx_int_t ngx_http_auth_spnego_set_variable(ngx_http_request_t *r,
                                                   ngx_str_t *name,
                                                   ngx_str_t *value) {
    ngx_http_auth_spnego_ctx_t *ctx;
    ngx_http_variable_value_t *v;

    if (name->len != sizeof(CCACHE_VARIABLE_NAME) - 1
        || ngx_strncmp(name->data, CCACHE_VARIABLE_NAME, name->len) != 0)
    {
        /* All callers pass static lowercase string literals, as
         * ngx_http_get_variable() does a byte-for-byte compare against the
         * stored (lowercased) name. */
        v = ngx_http_get_variable(r, name, ngx_hash_key(name->data, name->len));
        if (v == NULL) {
            return NGX_ERROR;
        }

        v->len = value->len;
        v->data = value->data;
        v->valid = 1;
        v->not_found = 0;
        v->no_cacheable = 0;

        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_spnego_module);
    if (ctx != NULL) {
        ctx->ccache = *value;
        v = ngx_http_auth_spnego_indexed_variable(r, name);
        if (v != NULL) {
            *v = ngx_http_variable_null_value;
            v->valid = 0;
        }
    }
    return NGX_OK;
}


static ngx_int_t ngx_http_auth_spnego_add_variable(ngx_conf_t *cf,
                                                   ngx_str_t *name,
                                                   ngx_http_get_variable_pt get) {
    ngx_http_variable_t *var =
        ngx_http_add_variable(cf, name, 0);

    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = get;
    var->data = 0;

    /*
     * Index the variable so ngx_http_get_variable() uses r->variables[index]
     * (a stable, zero-initialized per-request slot) rather than allocating a
     * fresh ngx_http_variable_value_t via ngx_palloc() on each call.  Without
     * this, set_variable() and the Lua ngx.var accessor each receive a
     * different, uninitialized vv pointer: the Lua read sees heap garbage from
     * recycled pool memory and lj_str_new() crashes on the bogus length.
     */
    if (ngx_http_get_variable_index(cf, name) == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_auth_spnego_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_auth_spnego_header_filter;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_spnego_handler;

    ngx_str_t var_name = ngx_string(CCACHE_VARIABLE_NAME);
    if (ngx_http_auth_spnego_add_variable(cf, &var_name,
                                          ngx_http_auth_spnego_get_handler)
        != NGX_OK) {
        return NGX_ERROR;
    }

    {
        ngx_http_variable_t *ev;
        ngx_str_t export_var_name = ngx_string(CRED_EXPORT_VARIABLE_NAME);
        ev = ngx_http_add_variable(cf, &export_var_name, NGX_HTTP_VAR_CHANGEABLE);
        if (ev == NULL)
            return NGX_ERROR;
        ev->get_handler = ngx_http_auth_spnego_exported_cred_variable;
    }

    ngx_str_t session_principal_var = ngx_string(SESSION_PRINCIPAL_VARIABLE_NAME);
    if (ngx_http_auth_spnego_add_variable(cf, &session_principal_var,
                                          ngx_http_auth_spnego_get_plain_handler)
        != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_str_t auth_type_var = ngx_string(AUTH_TYPE_VARIABLE_NAME);
    if (ngx_http_auth_spnego_add_variable(cf, &auth_type_var,
                                          ngx_http_auth_spnego_get_plain_handler)
        != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * This function exists only to identify the cleanup entry holding our
 * saved context. After an internal redirect, ngx_http_auth_spnego_get_ctx()
 * finds that entry by comparing its handler to this function's address.
 * The body is deliberately empty because nginx frees the context memory
 * when it destroys the request pool. Note that nginx does something similar
 * with its ngx_http_realip_get_module_ctx() function in
 * src/http/modules/ngx_http_realip_module.c.
 */
static void
ngx_http_auth_spnego_cleanup(void *data) {
}


/* Only saved logins are recovered here. An attached context may describe a
 * failed attempt, and must not replace a saved login in variable reads. */
static ngx_http_auth_spnego_ctx_t *
ngx_http_auth_spnego_get_ctx(ngx_http_request_t *r) {
    ngx_http_auth_spnego_ctx_t *ctx;
    ngx_pool_cleanup_t *cln;

    for (cln = r->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_auth_spnego_cleanup) {
            ctx = cln->data;
            if (ctx->alcf != NULL) {
                return ctx;
            }
        }
    }

    return NULL;
}


/* Discarded logins cannot authenticate again, but public destinations keep
 * their delegated credentials. Server rewrite precedes location selection. */
static ngx_http_auth_spnego_ctx_t *
ngx_http_auth_spnego_saved_ccache(ngx_http_request_t *r) {
    ngx_http_auth_spnego_ctx_t *ctx;
    ngx_http_auth_spnego_loc_conf_t *alcf;
    ngx_http_core_main_conf_t *cmcf;
    ngx_pool_cleanup_t *cln;

    ctx = ngx_http_get_module_ctx(r->main, ngx_http_auth_spnego_module);
    if (ctx != NULL && ctx->ccache.data != NULL) {
        return ctx;
    }
    ctx = ngx_http_auth_spnego_get_ctx(r);
    if (ctx != NULL) {
        return ctx;
    }
    alcf = ngx_http_auth_spnego_ccache_conf(r);
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    /* After an internal redirect, server rewrite uses the server configuration.
     * Check protect only after destination selection at location rewrite.
     * location_rewrite_index is set even without location rewrite handlers. */
    if (alcf->protect
        && r->phase_handler
           >= (ngx_int_t) cmcf->phase_engine.location_rewrite_index) {
        return NULL;
    }
    for (cln = r->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_auth_spnego_cleanup) {
            ctx = cln->data;
            if (ctx->alcf == NULL && ctx->ccache.data != NULL) {
                return ctx;
            }
        }
    }
    return NULL;
}


static ngx_int_t
ngx_http_auth_spnego_header_filter(ngx_http_request_t *r)
{
    ngx_http_auth_spnego_ctx_t      *ctx;
    ngx_http_auth_spnego_loc_conf_t *alcf;
    ngx_str_t value;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_spnego_module);
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_spnego_module);

    if (ctx == NULL) {
        return ngx_http_next_header_filter(r);
    }

    /* After a redirect, 401 and 403 describe the destination's challenge or
     * refusal, so they do not carry the saved login's reply token. */
    if (ctx->redirected) {
        if (r->headers_out.status    == NGX_HTTP_UNAUTHORIZED
            || r->headers_out.status == NGX_HTTP_FORBIDDEN) {
            return ngx_http_next_header_filter(r);
        }
    }

    if (ctx->ret == NGX_OK && ctx->token_out_b64.len > 0) {
        value.len = sizeof("Negotiate ") - 1 + ctx->token_out_b64.len;
        value.data = ngx_pnalloc(r->pool, value.len);
        if (value.data == NULL) {
            return NGX_ERROR;
        }
        ngx_snprintf(value.data, value.len, "Negotiate %V", &ctx->token_out_b64);

        if (ngx_http_auth_spnego_add_www_authenticate(r, &value, 1) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ctx->session_cookie_val.len > 0 && ctx->ret == NGX_OK) {
        ngx_table_elt_t *h;
        /* Build: "<name>=<value>; Max-Age=<N>; <attrs>" */
        static const char max_age_prefix[] = "; Max-Age=";
        char max_age_str[NGX_INT_T_LEN + 1];
        size_t max_age_len;

        max_age_len = ngx_snprintf((u_char *)max_age_str, sizeof(max_age_str),
                                   "%i%Z", (ngx_int_t)ctx->session_expiry)
                      - (u_char *)max_age_str - 1;

        value.len = ctx->session_cookie_name.len + 1 /* = */
                    + ctx->session_cookie_val.len
                    + (sizeof(max_age_prefix) - 1)
                    + max_age_len
                    + 2 /* "; " */
                    + alcf->session_cookie_attrs.len;
        value.data = ngx_pnalloc(r->pool, value.len);
        if (value.data == NULL) {
            return NGX_ERROR;
        }

        u_char *p = value.data;
        p = ngx_cpymem(p, ctx->session_cookie_name.data,
                       ctx->session_cookie_name.len);
        *p++ = '=';
        p = ngx_cpymem(p, ctx->session_cookie_val.data,
                       ctx->session_cookie_val.len);
        p = ngx_cpymem(p, max_age_prefix, sizeof(max_age_prefix) - 1);
        p = ngx_cpymem(p, max_age_str, max_age_len);
        *p++ = ';'; *p++ = ' ';
        p = ngx_cpymem(p, alcf->session_cookie_attrs.data,
                       alcf->session_cookie_attrs.len);
        value.len = p - value.data;

        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }
        h->hash = 1;
#if defined(nginx_version) && nginx_version >= 1023000
        h->next = NULL;
#endif
        h->key.len = sizeof("Set-Cookie") - 1;
        h->key.data = (u_char *)"Set-Cookie";
        h->value = value;
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_auth_spnego_add_www_authenticate(ngx_http_request_t *r,
                                          ngx_str_t *value, ngx_uint_t hash)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = hash;
#if defined(nginx_version) && nginx_version >= 1023000
    h->next = NULL;
#endif
    h->key.len = sizeof("WWW-Authenticate") - 1;
    h->key.data = (u_char *)"WWW-Authenticate";
    h->value = *value;

    r->headers_out.www_authenticate = h;
    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_spnego_add_basic_header(ngx_http_request_t *r,
                                      ngx_http_auth_spnego_loc_conf_t *alcf,
                                      ngx_uint_t hash)
{
    ngx_str_t value = ngx_null_string;
    value.len = sizeof("Basic realm=\"\", charset=\"UTF-8\"") - 1 + alcf->realm.len;
    value.data = ngx_pcalloc(r->pool, value.len);
    if (value.data == NULL) {
        return NGX_ERROR;
    }
    ngx_snprintf(value.data, value.len, "Basic realm=\"%V\", charset=\"UTF-8\"",
                 &alcf->realm);
    return ngx_http_auth_spnego_add_www_authenticate(r, &value, hash);
}


static ngx_int_t
ngx_http_auth_spnego_headers_basic_only(ngx_http_request_t *r,
                                        ngx_http_auth_spnego_ctx_t *ctx,
                                        ngx_http_auth_spnego_loc_conf_t *alcf) {
    if (ngx_http_auth_spnego_add_basic_header(r, alcf, 1) != NGX_OK) {
        return NGX_ERROR;
    }
    ctx->head = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_spnego_headers(ngx_http_request_t *r,
                             ngx_http_auth_spnego_ctx_t *ctx, ngx_str_t *token,
                             ngx_http_auth_spnego_loc_conf_t *alcf) {
    ngx_str_t value = ngx_null_string;

    if (token == NULL) {
        value.len = sizeof("Negotiate") - 1;
        value.data = (u_char *)"Negotiate";
    } else {
        value.len = sizeof("Negotiate") + token->len; /* \0 used for space */
        value.data = ngx_pcalloc(r->pool, value.len);
        if (value.data == NULL) {
            return NGX_ERROR;
        }
        ngx_snprintf(value.data, value.len, "Negotiate %V", token);
    }

    if (ngx_http_auth_spnego_add_www_authenticate(r, &value, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    if (alcf->allow_basic) {
        if (ngx_http_auth_spnego_add_basic_header(r, alcf, 2) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ctx->head = 1;
    return NGX_OK;
}


static bool
ngx_spnego_authorized_principal(ngx_http_request_t *r, ngx_str_t *princ,
                                ngx_http_auth_spnego_loc_conf_t *alcf) {
    if (NGX_CONF_UNSET_PTR == alcf->auth_princs
#if (NGX_PCRE)
        && NGX_CONF_UNSET_PTR == alcf->auth_princs_regex
#endif
    ) {
        return true;
    }

    if (NGX_CONF_UNSET_PTR != alcf->auth_princs) {
        spnego_debug1("Testing against %d auth princs",
                      alcf->auth_princs->nelts);

        ngx_str_t *auth_princs = alcf->auth_princs->elts;
        size_t i = 0;
        for (; i < alcf->auth_princs->nelts; ++i) {
            if (auth_princs[i].len != princ->len) {
                continue;
            }
            if (ngx_strncmp(auth_princs[i].data, princ->data, princ->len) ==
                0) {
                spnego_debug2("Authorized user %.*s", princ->len, princ->data);
                return true;
            }
        }
    }
#if (NGX_PCRE)
    if (NGX_CONF_UNSET_PTR != alcf->auth_princs_regex) {
        spnego_debug1("Testing against %d auth princs regex",
                      alcf->auth_princs_regex->nelts);

        if (ngx_regex_exec_array(alcf->auth_princs_regex, princ,
                                 r->connection->log) == NGX_OK) {
            return true;
        }
    }
#endif

    return false;
}


ngx_int_t ngx_http_auth_spnego_token(ngx_http_request_t *r,
                                     ngx_http_auth_spnego_ctx_t *ctx) {
    ngx_str_t token;
    ngx_str_t decoded;
    size_t nego_sz = sizeof("Negotiate");

    if (r->headers_in.authorization == NULL) {
        return NGX_DECLINED;
    }

    /* defensive guard: skip re-decoding */
    if (ctx->token.len)
        return NGX_OK;

    token = r->headers_in.authorization->value;

    if (token.len < nego_sz ||
        ngx_strncasecmp(token.data, (u_char *)"Negotiate ", nego_sz) != 0) {
        return NGX_DECLINED;
    }

    token.len -= nego_sz;
    token.data += nego_sz;

    while (token.len && token.data[0] == ' ') {
        token.len--;
        token.data++;
    }

    if (token.len == 0) {
        return NGX_DECLINED;
    }

    decoded.len = ngx_base64_decoded_length(token.len);
    decoded.data = ngx_pnalloc(r->pool, decoded.len);
    if (decoded.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&decoded, &token) != NGX_OK) {
        return NGX_DECLINED;
    }

    ctx->token.len = decoded.len;
    ctx->token.data = decoded.data;
    spnego_debug1("Token (base64), length: %uz", token.len);

    return NGX_OK;
}



#ifdef NGX_HAVE_CRED_STORE
static ngx_int_t
ngx_http_auth_spnego_store_delegated_creds(ngx_http_request_t *r,
                                           const char *principal_name,
                                           gss_cred_id_t delegated_creds,
                                           const char *ccache_dir) {
    OM_uint32 major_status, minor_status;
    const char *s;
    u_char *p, *escaped;
    size_t elen;
    char *ccname;
    size_t ccname_len;

    /* Escape principal name for use as a filename: '~' -> '~~', '/' -> '~' */
    elen = 0;
    for (s = principal_name; *s; s++)
        elen += (*s == '~') ? 2 : 1;
    escaped = ngx_palloc(r->pool, elen + 1);
    if (escaped == NULL) {
        spnego_log_error("Not enough memory");
        return NGX_ERROR;
    }
    p = escaped;
    for (s = principal_name; *s; s++) {
        if (*s == '~') { *p++ = '~'; *p++ = '~'; }
        else if (*s == '/') { *p++ = '~'; }
        else { *p++ = *s; }
    }
    *p = '\0';

    /* "FILE:" + ccache_dir + "/" + escaped + NUL */
    ccname_len = 5 + ngx_strlen(ccache_dir) + 1 + elen + 1;
    ccname = ngx_palloc(r->pool, ccname_len);
    if (ccname == NULL) {
        spnego_log_error("Not enough memory");
        return NGX_ERROR;
    }
    ngx_snprintf((u_char *)ccname, ccname_len, "FILE:%s/%s%Z",
                 ccache_dir, escaped);

    {
        gss_key_value_element_desc elem = { "ccache", ccname };
        gss_key_value_set_desc store = { 1, &elem };
        major_status = gss_store_cred_into(&minor_status, delegated_creds,
                                           GSS_C_INITIATE, GSS_C_NULL_OID,
                                           1, 0, &store, NULL, NULL);
    }
    if (GSS_ERROR(major_status)) {
        spnego_log_error("%s", get_gss_error(r->pool, major_status, minor_status,
                                             "gss_store_cred_into() failed"));
        return NGX_ERROR;
    }

    ngx_str_t var_name = ngx_string(CCACHE_VARIABLE_NAME);
    ngx_str_t var_value = { ngx_strlen(ccname), (u_char *)ccname };
    if (ngx_http_auth_spnego_set_variable(r, &var_name, &var_value) != NGX_OK) {
        spnego_log_error("failed to set $" CCACHE_VARIABLE_NAME);
        return NGX_ERROR;
    }

    return NGX_OK;
}
#endif /* NGX_HAVE_CRED_STORE */


/*
 * Return a pointer to the start of the realm part (i.e. after the
 * first unescaped '@').
 */
static u_char *
ngx_http_auth_spnego_realm_from_str(ngx_str_t s, size_t *realm_len)
{
    u_char *p, *at = NULL;
    u_char prev = 0;

    for (p = s.data; p < s.data + s.len; p++) {
        if (prev == '\\' && *p == '\\') {
            prev = 0;
            continue;
        } else if (*p == '@' && prev != '\\') {
            at = p;
            break;
        }
        prev = *p;
    }

    if (at == NULL)
        return NULL;

    if (realm_len)
        *realm_len = (size_t)(s.data + s.len - (at + 1));

    return at + 1;
}

/*
 * get_handler for $krb5_exported_cred: lazily derive the base64-encoded GSS
 * credential from the on-disk ccache written by store_delegated_creds().
 * Called only when the variable is actually referenced in the nginx config.
 */
static ngx_int_t
ngx_http_auth_spnego_exported_cred_variable(ngx_http_request_t *r,
                                            ngx_http_variable_value_t *v,
                                            uintptr_t data)
{
    v->not_found = 1;
#ifdef NGX_HAVE_CRED_STORE
    ngx_http_auth_spnego_ctx_t *ctx;
    gss_cred_id_t               gss_creds = GSS_C_NO_CREDENTIAL;
    OM_uint32                   major_status, minor_status = 0;
    gss_buffer_desc             token = GSS_C_EMPTY_BUFFER;
    ngx_str_t                   raw, b64;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_spnego_module);
    if (ctx == NULL || ctx->ccache.len == 0)
        return NGX_OK;

    {
        gss_key_value_element_desc elem = { "ccache", (char *)ctx->ccache.data };
        gss_key_value_set_desc store = { 1, &elem };
        major_status = gss_acquire_cred_from(&minor_status, GSS_C_NO_NAME,
                                             GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                                             GSS_C_INITIATE, &store,
                                             &gss_creds, NULL, NULL);
    }
    if (GSS_ERROR(major_status))
        goto done;

    major_status = gss_export_cred(&minor_status, gss_creds, &token);
    if (GSS_ERROR(major_status))
        goto done;

    raw.data = (u_char *)token.value;
    raw.len  = token.length;
    b64.len  = ngx_base64_encoded_length(raw.len);
    b64.data = ngx_pnalloc(r->pool, b64.len + 1);
    if (b64.data == NULL)
        goto done;

    ngx_encode_base64(&b64, &raw);
    b64.data[b64.len] = '\0';

    v->data        = b64.data;
    v->len         = b64.len;
    v->valid       = 1;
    v->no_cacheable = 0;
    v->not_found   = 0;

done:
    gss_release_buffer(&minor_status, &token);
    if (gss_creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&minor_status, &gss_creds);
#endif /* NGX_HAVE_CRED_STORE */
    return NGX_OK;
}





#if (NGX_HTTP_SSL)

#define SPNEGO_SESSION_NONCE_LEN  12
#define SPNEGO_SESSION_TAG_LEN    16

/* Fields stored in each encrypted session cookie. */
typedef struct {
    ngx_int_t  expiry;        /* Unix expiry timestamp */
    char      *username;      /* local username ($remote_user), NUL-terminated */
    char      *gssname;       /* full GSS name ($krb5_session_principal), NUL-terminated */
    char      *ccname;        /* delegated ccache name, NUL-terminated, may be "" */
    uint8_t    basichash[32]; /* HMAC-SHA256(key, user+'\0'+password), all-zeros if absent */
    ngx_int_t  has_basichash; /* 1 if basichash is valid (Basic Auth session) */
} ngx_http_auth_spnego_session_t;


/*
 * HMAC-SHA256(key[32], user + '\0' + password) → mac[32].
 * Returns NGX_OK on success, NGX_ERROR otherwise.
 */
static ngx_int_t
ngx_http_auth_spnego_session_hmac(ngx_pool_t *pool, const uint8_t *key,
                                  EVP_MAC *m,
                                  const u_char *user, size_t ulen,
                                  const u_char *pwd,  size_t plen,
                                  uint8_t mac[32])
{
    unsigned char  *data;
    EVP_MAC_CTX    *mctx = NULL;
    OSSL_PARAM      params[2];
    size_t          mac_len = 32;
    ngx_int_t       ret     = NGX_ERROR;

    data = ngx_palloc(pool, ulen + 1 + plen);
    if (data == NULL)
        return NGX_ERROR;

    ngx_memcpy(data, user, ulen);
    data[ulen] = '\0';
    ngx_memcpy(data + ulen + 1, pwd, plen);

    mctx = EVP_MAC_CTX_new(m);
    if (mctx == NULL)
        goto done;

    params[0] = OSSL_PARAM_construct_utf8_string(
                    OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(mctx, key, 32, params) != 1)
        goto done;
    if (EVP_MAC_update(mctx, data, ulen + 1 + plen) != 1)
        goto done;
    if (EVP_MAC_final(mctx, mac, &mac_len, 32) != 1)
        goto done;
    ret = NGX_OK;

done:
    EVP_MAC_CTX_free(mctx);
    ngx_explicit_memzero(data, ulen + 1 + plen);
    return ret;
}


/*
 * Write one netstring "<len>:<data>," into [*p, end).
 * Advances *p past the written bytes.  Returns 1 on success, 0 if the buffer
 * is too small.
 */
static int
ngx_spnego_ns_write(u_char **p, u_char *end, const void *data, size_t dlen)
{
    u_char  nbuf[24];
    size_t  nlen;

    nlen = ngx_snprintf(nbuf, sizeof(nbuf), "%uz", dlen) - nbuf;
    if ((size_t)(end - *p) < nlen + 1 + dlen + 1)
        return 0;
    ngx_memcpy(*p, nbuf, nlen);  *p += nlen;
    **p = ':';                    (*p)++;
    if (dlen)
        ngx_memcpy(*p, data, dlen);
    *p  += dlen;
    **p  = ',';                   (*p)++;
    return 1;
}

/*
 * Read one netstring from [*p, end).
 * On success sets *data_out / *len_out and advances *p.  Returns 1 on
 * success, 0 on any parse error (missing colon/comma, truncated data, etc.).
 * Length fields wider than 4 digits are rejected to avoid size_t overflow;
 * the plaintext is capped at 2048 bytes, so no valid field is longer.
 */
static int
ngx_spnego_ns_read(const u_char **p, const u_char *end,
                   const u_char **data_out, size_t *len_out)
{
    const u_char *q   = *p;
    size_t        len = 0;
    int           nd  = 0;

    while (q < end && *q >= '0' && *q <= '9') {
        len = len * 10 + (*q - '0');
        q++;
        nd++;
    }
    if (nd == 0 || nd > 4 || q >= end || *q != ':')
        return 0;
    q++;  /* skip ':' */
    if ((size_t)(end - q) < len + 1 || q[len] != ',')
        return 0;
    *data_out = q;
    *len_out  = len;
    *p = q + len + 1;
    return 1;
}


/*
 * Encrypt session data with AES-256-GCM-SIV and return the result as a
 * base64 string suitable for a cookie value.
 *
 * Plaintext is 5 consecutive netstrings:
 *   NS(expiry_ts) NS(ccname) NS(username) NS(gssname) NS(basichash)
 *
 * basichash: 32 raw bytes (HMAC-SHA256), or empty if absent.
 * Binary layout: [12-byte nonce][ciphertext][16-byte GCM-SIV tag]
 */
static ngx_str_t
ngx_http_auth_spnego_encrypt_session(ngx_pool_t *pool,
                                     const uint8_t *key,
                                     const EVP_CIPHER *aead,
                                     const u_char *aad,
                                     size_t aad_len,
                                     const char *username,
                                     const char *gssname,
                                     const char *ccname,
                                     const uint8_t *basichash,
                                     ngx_int_t expiry_ts)
{
    ngx_str_t       result = ngx_null_string;
    EVP_CIPHER_CTX *ctx    = NULL;
    unsigned char   nonce[SPNEGO_SESSION_NONCE_LEN];
    /* 2048 B cap: base64(nonce + 2048 + tag) ≈ 2768 B cookie value, safely under the 4096 B browser limit */
    unsigned char   plaintext[2048];
    int             pt_len, ct_len, fin_len;
    u_char         *buf, *p;
    size_t          buf_len;
    ngx_str_t       raw;

    {
        u_char  expiry_buf[24];
        size_t  expiry_len = ngx_snprintf(expiry_buf, sizeof(expiry_buf),
                                          "%i", expiry_ts) - expiry_buf;
        u_char *pt         = plaintext;
        u_char *pt_end     = plaintext + sizeof(plaintext);

        if (!ngx_spnego_ns_write(&pt, pt_end, expiry_buf, expiry_len)
            || !ngx_spnego_ns_write(&pt, pt_end,
                                    ccname ? ccname : "",
                                    ccname ? ngx_strlen(ccname) : 0)
            || !ngx_spnego_ns_write(&pt, pt_end, username, ngx_strlen(username))
            || !ngx_spnego_ns_write(&pt, pt_end, gssname, ngx_strlen(gssname))
            || !ngx_spnego_ns_write(&pt, pt_end,
                                    basichash ? basichash : (const uint8_t *)"",
                                    basichash ? 32 : 0))
            goto done;

        pt_len = (int)(pt - plaintext);
    }

    if (RAND_bytes(nonce, SPNEGO_SESSION_NONCE_LEN) != 1)
        goto done;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto done;

    if (EVP_EncryptInit_ex(ctx, aead, NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto done;
    {
        int aad_out;
        if (EVP_EncryptUpdate(ctx, NULL, &aad_out,
                              aad, (int)aad_len) != 1)
            goto done;
    }

    buf_len = SPNEGO_SESSION_NONCE_LEN + pt_len + SPNEGO_SESSION_TAG_LEN;
    buf = ngx_palloc(pool, buf_len);
    if (buf == NULL)
        goto done;

    p = buf;
    ngx_memcpy(p, nonce, SPNEGO_SESSION_NONCE_LEN);
    p += SPNEGO_SESSION_NONCE_LEN;

    if (EVP_EncryptUpdate(ctx, p, &ct_len, plaintext, pt_len) != 1)
        goto done;
    p += ct_len;

    if (EVP_EncryptFinal_ex(ctx, p, &fin_len) != 1)
        goto done;
    p += fin_len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                             SPNEGO_SESSION_TAG_LEN, p) != 1)
        goto done;

    raw.data = buf;
    raw.len  = buf_len;

    result.len  = ngx_base64_encoded_length(buf_len);
    result.data = ngx_palloc(pool, result.len + 1);
    if (result.data == NULL) {
        result = (ngx_str_t)ngx_null_string;
        goto done;
    }
    ngx_encode_base64(&result, &raw);
    result.data[result.len] = '\0';

done:
    ngx_explicit_memzero(plaintext, sizeof(plaintext));
    EVP_CIPHER_CTX_free(ctx);
    return result;
}


/*
 * Decrypt and authenticate a session cookie value (base64-encoded).
 * Returns a pool-allocated ngx_http_auth_spnego_session_t, or NULL on any
 * error (decryption failure, bad MAC, or expired session).
 */
static ngx_http_auth_spnego_session_t *
ngx_http_auth_spnego_decrypt_session(ngx_pool_t *pool,
                                     const uint8_t *key,
                                     const EVP_CIPHER *aead,
                                     const u_char *aad,
                                     size_t aad_len,
                                     ngx_str_t *cookie_val)
{
    EVP_CIPHER_CTX                *ctx  = NULL;
    ngx_str_t                      raw;
    unsigned char                  tag[SPNEGO_SESSION_TAG_LEN];
    unsigned char                  plaintext[2048];
    ngx_http_auth_spnego_session_t *sess = NULL;
    int                            pt_len, fin_len;
    size_t                         ct_len_sz;

    /* A valid cookie value is base64(nonce + ≤2048 + tag) ≈ 2768 bytes;
     * reject anything larger before allocating its decoded buffer. */
    if (cookie_val->len == 0 || cookie_val->len > 4096)
        return NULL;

    raw.len  = ngx_base64_decoded_length(cookie_val->len);
    raw.data = ngx_palloc(pool, raw.len);
    if (raw.data == NULL)
        return NULL;

    if (ngx_decode_base64(&raw, cookie_val) != NGX_OK)
        return NULL;

    if (raw.len < SPNEGO_SESSION_NONCE_LEN + 1 + SPNEGO_SESSION_TAG_LEN)
        return NULL;

    ct_len_sz = raw.len - SPNEGO_SESSION_NONCE_LEN - SPNEGO_SESSION_TAG_LEN;
    if (ct_len_sz >= sizeof(plaintext))
        return NULL;

    ngx_memcpy(tag,
               raw.data + SPNEGO_SESSION_NONCE_LEN + ct_len_sz,
               SPNEGO_SESSION_TAG_LEN);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return NULL;

    if (EVP_DecryptInit_ex(ctx, aead, NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, raw.data) != 1)
        goto done;
    {
        int aad_out;
        if (EVP_DecryptUpdate(ctx, NULL, &aad_out,
                              aad, (int)aad_len) != 1)
            goto done;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             SPNEGO_SESSION_TAG_LEN, tag) != 1)
        goto done;
    if (EVP_DecryptUpdate(ctx, plaintext, &pt_len,
                          raw.data + SPNEGO_SESSION_NONCE_LEN,
                          (int)ct_len_sz) != 1)
        goto done;
    if (EVP_DecryptFinal_ex(ctx, plaintext + pt_len, &fin_len) != 1)
        goto done;

    pt_len += fin_len;

    /* Parse 5 netstring fields: expiry, ccname, username, gssname, basichash */
    {
        const u_char *p   = plaintext;
        const u_char *end = plaintext + pt_len;
        const u_char *f_data;
        size_t        f_len;
        ngx_int_t     expiry;
        u_char       *cptr, *uptr, *gptr;

        if (!ngx_spnego_ns_read(&p, end, &f_data, &f_len))
            goto done;
        expiry = ngx_atoi((u_char *)f_data, f_len);
        if (expiry == NGX_ERROR || expiry < (ngx_int_t)ngx_time())
            goto done;

        if (!ngx_spnego_ns_read(&p, end, &f_data, &f_len))
            goto done;
        cptr = ngx_pnalloc(pool, f_len + 1);
        if (cptr == NULL) goto done;
        ngx_memcpy(cptr, f_data, f_len);
        cptr[f_len] = '\0';

        if (!ngx_spnego_ns_read(&p, end, &f_data, &f_len) || f_len == 0)
            goto done;
        uptr = ngx_pnalloc(pool, f_len + 1);
        if (uptr == NULL) goto done;
        ngx_memcpy(uptr, f_data, f_len);
        uptr[f_len] = '\0';

        if (!ngx_spnego_ns_read(&p, end, &f_data, &f_len) || f_len == 0)
            goto done;
        gptr = ngx_pnalloc(pool, f_len + 1);
        if (gptr == NULL) goto done;
        ngx_memcpy(gptr, f_data, f_len);
        gptr[f_len] = '\0';

        /* basichash: absent (0 bytes) or exactly 32 raw bytes */
        if (!ngx_spnego_ns_read(&p, end, &f_data, &f_len))
            goto done;
        if (f_len != 0 && f_len != 32)
            goto done;

        sess = ngx_pcalloc(pool, sizeof(*sess));
        if (sess == NULL) goto done;

        sess->expiry    = expiry;
        sess->ccname    = (char *)cptr;
        sess->username  = (char *)uptr;
        sess->gssname   = (char *)gptr;

        if (f_len == 32) {
            ngx_memcpy(sess->basichash, f_data, 32);
            sess->has_basichash = 1;
        }
    }

done:
    ngx_explicit_memzero(plaintext, sizeof(plaintext));
    EVP_CIPHER_CTX_free(ctx);
    return sess;
}


/*
 * Search the Cookie request header for a cookie named <name>.
 * Returns the raw (URL-encoded) value, or ngx_null_string if not found.
 */
static ngx_str_t
ngx_http_auth_spnego_find_cookie(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_str_t    result = ngx_null_string;
    ngx_list_part_t *part;
    ngx_table_elt_t *hdrs;
    ngx_uint_t       i;

    part = &r->headers_in.headers.part;
    hdrs = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL)
                break;
            part = part->next;
            hdrs = part->elts;
            i = 0;
        }
        if (hdrs[i].hash == 0)
            continue;
        if (hdrs[i].key.len != sizeof("Cookie") - 1)
            continue;
        if (ngx_strncasecmp(hdrs[i].key.data, (u_char *)"Cookie",
                            sizeof("Cookie") - 1) != 0)
            continue;

        /* scan this Cookie header's value */
        u_char *p   = hdrs[i].value.data;
        u_char *end = p + hdrs[i].value.len;

        while (p < end) {
            while (p < end && (*p == ' ' || *p == '\t'))
                p++;
            if (p >= end)
                break;

            u_char *eq = p;
            while (eq < end && *eq != '=')
                eq++;
            if (eq >= end)
                break;

            size_t nlen = (size_t)(eq - p);
            while (nlen > 0
                   && (p[nlen - 1] == ' ' || p[nlen - 1] == '\t'))
                nlen--;

            u_char *semi = eq + 1;
            while (semi < end && *semi != ';')
                semi++;

            if (nlen == name->len
                && ngx_strncmp(p, name->data, nlen) == 0)
            {
                result.data = eq + 1;
                result.len  = (size_t)(semi - (eq + 1));
                while (result.len > 0 && *result.data == ' ') {
                    result.data++;
                    result.len--;
                }
                while (result.len > 0
                       && result.data[result.len - 1] == ' ')
                    result.len--;
                /* RFC 6265 allows DQUOTE-wrapped values; strip a matching
                 * pair so non-browser clients that quote the value still
                 * decrypt correctly.  nginx's own cookie parser does not
                 * strip these. */
                if (result.len >= 2
                    && result.data[0] == '"'
                    && result.data[result.len - 1] == '"')
                {
                    result.data++;
                    result.len -= 2;
                }
                return result;
            }

            p = semi;
            if (p < end)
                p++;  /* skip ';' */
        }
    }

    return result;
}
#endif /* NGX_HTTP_SSL */

#if (NGX_HTTP_SSL)
static void
ngx_http_auth_spnego_set_session_cookie(ngx_http_request_t *r,
                                        ngx_http_auth_spnego_ctx_t *ctx,
                                        ngx_http_auth_spnego_loc_conf_t *alcf,
                                        OM_uint32 time_rec,
                                        const char *gssname,
                                        const uint8_t *basichash)
{
    if (!alcf->session_key_loaded || alcf->session_expiry <= 0
        || r->headers_in.user.len == 0)
        return;

    char *user_nul = ngx_pnalloc(r->pool, r->headers_in.user.len + 1);
    if (user_nul == NULL)
        return;
    ngx_memcpy(user_nul, r->headers_in.user.data, r->headers_in.user.len);
    user_nul[r->headers_in.user.len] = '\0';

    OM_uint32 ticket_secs = (time_rec == GSS_C_INDEFINITE)
        ? (OM_uint32)alcf->session_expiry : time_rec;
    ngx_int_t expiry_ts = (ngx_int_t)(ngx_time()
        + ngx_min((OM_uint32)alcf->session_expiry, ticket_secs));

    ctx->session_cookie_val = ngx_http_auth_spnego_encrypt_session(
        r->pool, alcf->session_enc_key, alcf->session_cipher,
        alcf->session_aad, alcf->session_aad_len,
        user_nul,
        gssname ? gssname : user_nul,
        ctx->ccache.len > 0 ? (char *)ctx->ccache.data : "",
        basichash,
        expiry_ts);
    ctx->session_cookie_name = alcf->session_cookie_name;
    ctx->session_expiry      = (ngx_int_t)ngx_min((OM_uint32)alcf->session_expiry, ticket_secs);
    if (ctx->session_cookie_val.len == 0)
        spnego_log_error("failed to encrypt session cookie");
}
#endif /* NGX_HTTP_SSL */

#ifdef NGX_HAVE_CRED_STORE
static ngx_int_t ngx_http_auth_spnego_ensure_constrained_creds(
    ngx_http_request_t *r, ngx_http_auth_spnego_loc_conf_t *alcf,
    gss_name_t svc_name);
#endif


ngx_int_t ngx_http_auth_spnego_basic(ngx_http_request_t *r,
                                     ngx_http_auth_spnego_ctx_t *ctx,
                                     ngx_http_auth_spnego_loc_conf_t *alcf) {
    ngx_str_t user;
    user.data = NULL;
    ngx_str_t new_user;
    ngx_int_t ret = NGX_DECLINED;

    OM_uint32 major_status, minor_status, time_rec;
    gss_name_t    client_name    = GSS_C_NO_NAME;
    gss_name_t    service_name   = GSS_C_NO_NAME;
    gss_name_t    src_name       = GSS_C_NO_NAME;
    gss_cred_id_t user_cred      = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t acceptor_cred  = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t  init_ctx       = GSS_C_NO_CONTEXT;
    gss_ctx_id_t  accept_ctx     = GSS_C_NO_CONTEXT;
    gss_buffer_desc token     = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc reply     = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc passwd_buf = GSS_C_EMPTY_BUFFER;
    char *name = NULL;
    u_char *realm = NULL;
    size_t realm_len = 0;

    realm = ngx_http_auth_spnego_realm_from_str(r->headers_in.user, &realm_len);
    user.len = r->headers_in.user.len + 1;
    if (realm == NULL) {
        if (alcf->force_realm && alcf->realm.len && alcf->realm.data) {
            user.len += alcf->realm.len + 1; /* +1 for @ */
            user.data = ngx_palloc(r->pool, user.len);
            if (user.data == NULL) {
                spnego_log_error("Not enough memory");
                spnego_error(NGX_ERROR);
            }
            ngx_snprintf(user.data, user.len, "%V@%V%Z", &r->headers_in.user,
                         &alcf->realm);
        } else {
            user.data = ngx_palloc(r->pool, user.len);
            if (user.data == NULL) {
                spnego_log_error("Not enough memory");
                spnego_error(NGX_ERROR);
            }
            ngx_snprintf(user.data, user.len, "%V%Z", &r->headers_in.user);
        }
    } else {
        if (alcf->realm.len && alcf->realm.data &&
            realm_len == alcf->realm.len &&
            ngx_strncmp(realm, alcf->realm.data, alcf->realm.len) == 0) {
            user.data = ngx_palloc(r->pool, user.len);
            if (user.data == NULL) {
                spnego_log_error("Not enough memory");
                spnego_error(NGX_ERROR);
            }
            ngx_snprintf(user.data, user.len, "%V%Z", &r->headers_in.user);
            ngx_http_auth_spnego_strip_realm(r, alcf);
        } else if (alcf->force_realm) {
            ngx_str_t short_user;

            short_user.data = r->headers_in.user.data;
            short_user.len = (realm - 1) - r->headers_in.user.data;
            user.len = short_user.len + 1;
            if (alcf->realm.len && alcf->realm.data)
                user.len += alcf->realm.len + 1;
            user.data = ngx_pcalloc(r->pool, user.len);
            if (user.data == NULL) {
                spnego_log_error("Not enough memory");
                spnego_error(NGX_ERROR);
            }
            if (alcf->realm.len && alcf->realm.data)
                ngx_snprintf(user.data, user.len, "%V@%V%Z", &short_user,
                             &alcf->realm);
            else
                ngx_snprintf(user.data, user.len, "%V%Z", &short_user);
            /*
             * Rewrite $remote_user with the forced realm.
             * If the forced realm is shorter than the
             * specified realm, we can reuse the original
             * buffer.
             */
            if (r->headers_in.user.len >= user.len - 1)
                r->headers_in.user.len = user.len - 1;
            else {
                new_user.len = user.len - 1;
                new_user.data = ngx_palloc(r->pool, new_user.len);
                if (new_user.data == NULL) {
                    spnego_log_error("Not enough memory");
                    spnego_error(NGX_ERROR);
                }
                r->headers_in.user.data = new_user.data;
                r->headers_in.user.len = new_user.len;
            }
            ngx_memcpy(r->headers_in.user.data, user.data,
                       r->headers_in.user.len);
        } else {
            user.data = ngx_palloc(r->pool, user.len);
            if (user.data == NULL) {
                spnego_log_error("Not enough memory");
                spnego_error(NGX_ERROR);
            }
            ngx_snprintf(user.data, user.len, "%V%Z", &r->headers_in.user);
        }
    }

    spnego_debug1("Attempting authentication with principal %s",
                  (const char *)user.data);

    /* Import the client and service principal names */
    {
        gss_buffer_desc buf;
        buf.value  = user.data;
        buf.length = user.len - 1; /* exclude NUL terminator */
        major_status = gss_import_name(&minor_status, &buf,
                                       GSS_C_NT_USER_NAME,
                                       &client_name);
        if (GSS_ERROR(major_status)) {
            spnego_log_error("Cannot import client name \"%s\": %s",
                             (const char *)user.data,
                             get_gss_error(r->pool, major_status, minor_status,
                                           "gss_import_name() failed"));
            spnego_error(NGX_ERROR);
        }
    }
    {
        gss_buffer_desc buf;
        buf.value  = alcf->service_principal;
        buf.length = ngx_strlen(alcf->service_principal);
        major_status = gss_import_name(&minor_status, &buf,
                                       GSS_C_NO_OID,
                                       &service_name);
        if (GSS_ERROR(major_status)) {
            spnego_log_error("Cannot import service name \"%s\": %s",
                             alcf->service_principal,
                             get_gss_error(r->pool, major_status, minor_status,
                                           "gss_import_name() failed"));
            spnego_error(NGX_ERROR);
        }
    }

    /* Acquire a short-lived TGT for the user by presenting the password */
    {
        char *passwd = ngx_pnalloc(r->pool, r->headers_in.passwd.len + 1);
        if (passwd == NULL) {
            spnego_log_error("Not enough memory");
            spnego_error(NGX_ERROR);
        }
        ngx_memcpy(passwd, r->headers_in.passwd.data, r->headers_in.passwd.len);
        passwd[r->headers_in.passwd.len] = '\0';
        passwd_buf.value  = passwd;
        passwd_buf.length = r->headers_in.passwd.len;
    }

    {
        OM_uint32 tkt_life = (alcf->session_key_loaded && alcf->session_expiry > 0)
            ? (OM_uint32)alcf->session_expiry : BASIC_AUTH_TKT_LIFE;
        major_status = gss_acquire_cred_with_password(&minor_status, client_name,
                                                       &passwd_buf, tkt_life,
                                                       GSS_C_NO_OID_SET,
                                                       GSS_C_INITIATE,
                                                       &user_cred, NULL, NULL);
    }
    if (GSS_ERROR(major_status)) {
        spnego_log_error("Basic auth failed for \"%s\": %s",
                         (const char *)user.data,
                         get_gss_error(r->pool, major_status, minor_status,
                                       "gss_acquire_cred_with_password() failed"));
        spnego_error(NGX_DECLINED);
    }

    /* Acquire or reuse the acceptor credential */
#ifdef NGX_HAVE_CRED_STORE
    if (alcf->delegation & SPNEGO_DELEG_CONSTRAINED) {
        if (ngx_http_auth_spnego_ensure_constrained_creds(r, alcf,
                                                           service_name) != NGX_OK) {
            spnego_error(NGX_ERROR);
        }
        acceptor_cred = alcf->constrained_creds;
    } else
#endif
    {
#ifdef NGX_HAVE_GSS_ACQUIRE_CRED_FROM
        gss_key_value_element_desc elem;
        gss_key_value_set_desc store;

        elem.key   = "keytab";
        elem.value = alcf->keytab_prefix_path;
        store.count    = 1;
        store.elements = &elem;

        major_status = gss_acquire_cred_from(&minor_status, service_name,
                                              GSS_C_INDEFINITE,
                                              GSS_C_NO_OID_SET, GSS_C_ACCEPT,
                                              &store, &acceptor_cred, NULL, NULL);
#else
        /* No gss_acquire_cred_from() (Heimdal 7.x): fall back to the default
         * acceptor credential.  auth_gss_keytab cannot be honored on this
         * build; whatever GSSAPI defaults to (KRB5_KTNAME or
         * /etc/krb5.keytab) is used.  Mirrors mod_auth_gssapi.c:282-286. */
        major_status = gss_acquire_cred(&minor_status, service_name,
                                        GSS_C_INDEFINITE,
                                        GSS_C_NO_OID_SET, GSS_C_ACCEPT,
                                        &acceptor_cred, NULL, NULL);
#endif
        if (GSS_ERROR(major_status)) {
            spnego_log_error("Cannot acquire service credential from %s: %s",
                             alcf->keytab_prefix_path,
                             get_gss_error(r->pool, major_status, minor_status,
                                           "failed to acquire acceptor credential"));
            spnego_error(NGX_ERROR);
        }
    }

    /* Synthetic init/accept loop: verifies the TGT against the keytab and
     * produces a delegated_cred if GSS_C_DELEG_FLAG is requested. */
    {
        OM_uint32 req_flags = GSS_C_MUTUAL_FLAG;
#ifdef NGX_HAVE_CRED_STORE
        if (alcf->delegation & SPNEGO_DELEG_UNCONSTRAINED)
            req_flags |= GSS_C_DELEG_FLAG;
#endif

        major_status = gss_init_sec_context(&minor_status, user_cred, &init_ctx,
                                            service_name, GSS_C_NO_OID,
                                            req_flags, 0,
                                            GSS_C_NO_CHANNEL_BINDINGS,
                                            GSS_C_NO_BUFFER, NULL,
                                            &token, NULL, NULL);
        if (GSS_ERROR(major_status)) {
            spnego_log_error("Basic auth gss_init_sec_context failed: %s",
                             get_gss_error(r->pool, major_status, minor_status,
                                           "gss_init_sec_context() failed"));
            spnego_error(NGX_ERROR);
        }

        time_rec = GSS_C_INDEFINITE;
        major_status = gss_accept_sec_context(&minor_status, &accept_ctx,
                                              acceptor_cred, &token,
                                              GSS_C_NO_CHANNEL_BINDINGS,
                                              &src_name, NULL, &reply,
                                              NULL, &time_rec, &delegated_cred);
        gss_release_buffer(&minor_status, &token);

        if (GSS_ERROR(major_status)) {
            gss_release_buffer(&minor_status, &reply);
            spnego_log_error("Basic auth credential verification failed "
                             "(keytab %s, service %s): %s",
                             alcf->keytab_prefix_path, alcf->service_principal,
                             get_gss_error(r->pool, major_status, minor_status,
                                           "gss_accept_sec_context() failed"));
            spnego_error(NGX_ERROR);
        }

        /* Complete mutual authentication if the acceptor returned an AP-REP */
        if (reply.length > 0) {
            gss_buffer_desc dummy = GSS_C_EMPTY_BUFFER;
            gss_init_sec_context(&minor_status, user_cred, &init_ctx,
                                 service_name, GSS_C_NO_OID, req_flags, 0,
                                 GSS_C_NO_CHANNEL_BINDINGS, &reply,
                                 NULL, &dummy, NULL, NULL);
            gss_release_buffer(&minor_status, &reply);
            gss_release_buffer(&minor_status, &dummy);
        }
    }

    /* Extract the authenticated client's canonical name */
    {
        gss_buffer_desc disp = GSS_C_EMPTY_BUFFER;
        if (!GSS_ERROR(gss_display_name(&minor_status, src_name, &disp, NULL))) {
            name = ngx_palloc(r->pool, disp.length + 1);
            if (name != NULL) {
                ngx_memcpy(name, disp.value, disp.length);
                name[disp.length] = '\0';
            }
            gss_release_buffer(&minor_status, &disp);
        }
    }
    if (name == NULL || name[0] == '\0') {
        spnego_log_error("Cannot obtain authenticated principal name");
        spnego_error(NGX_ERROR);
    }


#ifdef NGX_HAVE_CRED_STORE
    if (alcf->delegation != SPNEGO_DELEG_OFF
        && delegated_cred != GSS_C_NO_CREDENTIAL) {
        if (ngx_http_auth_spnego_store_delegated_creds(r, name,
                                                       delegated_cred,
                                                       (char *)alcf->deleg_ccache_dir.data) != NGX_OK) {
            spnego_error(NGX_ERROR);
        }
    }
#endif

    /*
     * Set $remote_user from the GSS-verified canonical principal
     * (src_name), mirroring the SPNEGO path, instead of trusting the
     * client-typed username. This also feeds auth_gss_authorized_principal
     * below.
     */
    {
        gss_buffer_desc local_buf = GSS_C_EMPTY_BUFFER;
        ngx_str_t canon;

        if (alcf->map_to_local) {
            major_status = gss_localname(&minor_status, src_name,
                                          GSS_C_NO_OID, &local_buf);
            if (GSS_ERROR(major_status)) {
                spnego_log_error("%s", get_gss_error(r->pool, major_status,
                                     minor_status, "gss_localname() failed"));
                spnego_error(NGX_DECLINED);
            }
            canon.data = local_buf.value;
            canon.len  = local_buf.length;
        } else {
            canon.data = (u_char *) name;
            canon.len  = ngx_strlen(name);
        }

        if (canon.len == 0) {
            gss_release_buffer(&minor_status, &local_buf);
            spnego_log_error("Cannot map \"%s\" to a local user name", name);
            spnego_error(NGX_ERROR);
        }

        new_user.data = ngx_pnalloc(r->pool, canon.len);
        if (new_user.data == NULL) {
            gss_release_buffer(&minor_status, &local_buf);
            spnego_log_error("Not enough memory");
            spnego_error(NGX_ERROR);
        }
        ngx_memcpy(new_user.data, canon.data, canon.len);
        new_user.len = canon.len;
        gss_release_buffer(&minor_status, &local_buf);

        r->headers_in.user.data = new_user.data;
        r->headers_in.user.len  = new_user.len;
    }
    ngx_http_auth_spnego_strip_realm(r, alcf);

    /* Append Kerberos realm to $remote_user if not already present */
    if (alcf->fqun &&
        !ngx_http_auth_spnego_realm_from_str(r->headers_in.user, NULL)) {
        const char *realm_at = strrchr(name, '@');
        const char *krb5realm = (realm_at && realm_at[1]) ? realm_at + 1 : NULL;
        if (krb5realm) {
            new_user.len = r->headers_in.user.len + 1 + ngx_strlen(krb5realm);
            new_user.data = ngx_palloc(r->pool, new_user.len);
            if (new_user.data == NULL) {
                spnego_log_error("Not enough memory");
                spnego_error(NGX_ERROR);
            }
            ngx_snprintf(new_user.data, new_user.len, "%V@%s",
                         &r->headers_in.user, krb5realm);
            r->headers_in.user.data = new_user.data;
            r->headers_in.user.len = new_user.len;
        }
    }

    spnego_debug1("Setting $remote_user to %V", &r->headers_in.user);
    if (ngx_http_auth_spnego_set_bogus_authorization(r) != NGX_OK)
        spnego_log_error("Failed to set $remote_user");

    spnego_debug0("ngx_http_auth_spnego_basic: returning NGX_OK");

    {
        ngx_str_t at_var = ngx_string(AUTH_TYPE_VARIABLE_NAME);
        ngx_str_t at_val = ngx_string("basic");
        ngx_http_auth_spnego_set_variable(r, &at_var, &at_val);
    }

#if (NGX_HTTP_SSL)
    {
        uint8_t bh[32];
        const uint8_t *bh_ptr = NULL;
        if (alcf->session_key_loaded &&
                ngx_http_auth_spnego_session_hmac(r->pool, alcf->session_mac_key,
                        alcf->session_mac,
                        r->headers_in.user.data, r->headers_in.user.len,
                        r->headers_in.passwd.data, r->headers_in.passwd.len,
                        bh) == NGX_OK)
            bh_ptr = bh;
        ngx_http_auth_spnego_set_session_cookie(r, ctx, alcf, time_rec,
                                                name, bh_ptr);
        ngx_explicit_memzero(bh, sizeof(bh));
    }
#endif

    ret = NGX_OK;

end:
    if (init_ctx != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&minor_status, &init_ctx, GSS_C_NO_BUFFER);
    if (accept_ctx != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&minor_status, &accept_ctx, GSS_C_NO_BUFFER);
    if (delegated_cred != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&minor_status, &delegated_cred);
    if (user_cred != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&minor_status, &user_cred);
    if (acceptor_cred != GSS_C_NO_CREDENTIAL
#ifdef NGX_HAVE_CRED_STORE
        && acceptor_cred != alcf->constrained_creds
#endif
        )
        gss_release_cred(&minor_status, &acceptor_cred);
    if (client_name != GSS_C_NO_NAME)
        gss_release_name(&minor_status, &client_name);
    if (service_name != GSS_C_NO_NAME)
        gss_release_name(&minor_status, &service_name);
    if (src_name != GSS_C_NO_NAME)
        gss_release_name(&minor_status, &src_name);
    gss_release_buffer(&minor_status, &token);
    gss_release_buffer(&minor_status, &reply);
    if (passwd_buf.value != NULL)
        ngx_explicit_memzero(passwd_buf.value, passwd_buf.length);

    return ret;
}

/*
 * Conditionally strip the configured realm suffix from $remote_user.
 */
static void
ngx_http_auth_spnego_strip_realm(ngx_http_request_t *r,
                                  ngx_http_auth_spnego_loc_conf_t *alcf)
{
    u_char *realm;
    size_t rlen;

    if (alcf->fqun || !alcf->realm.len || !alcf->realm.data)
        return;

    realm = ngx_http_auth_spnego_realm_from_str(r->headers_in.user, &rlen);
    if (realm == NULL || rlen != alcf->realm.len)
        return;

    if (ngx_strncmp(realm, alcf->realm.data, alcf->realm.len) == 0)
        r->headers_in.user.len -= alcf->realm.len + 1;
}

/*
 * Because 'remote_user' is assumed to be provided by basic authorization
 * (see ngx_http_variable_remote_user) we are forced to create a bogus
 * non-Negotiate authorization header.  This is called only after the
 * Negotiate token has been fully consumed, so it does not interfere with
 * SPNEGO processing.
 */
ngx_int_t ngx_http_auth_spnego_set_bogus_authorization(ngx_http_request_t *r) {
    const char *bogus_passwd = "bogus_auth_gss_passwd";
    ngx_str_t plain, encoded, final;

    if (r->headers_in.user.len == 0) {
        spnego_debug0("ngx_http_auth_spnego_set_bogus_authorization: no user "
                      "NGX_DECLINED");
        return NGX_DECLINED;
    }

    /* +1 because of the ":" in "user:password" */
    plain.len = r->headers_in.user.len + ngx_strlen(bogus_passwd) + 1;
    plain.data = ngx_pnalloc(r->pool, plain.len);
    if (plain.data == NULL) {
        return NGX_ERROR;
    }

    ngx_snprintf(plain.data, plain.len, "%V:%s", &r->headers_in.user,
                 bogus_passwd);

    encoded.len = ngx_base64_encoded_length(plain.len);
    encoded.data = ngx_pnalloc(r->pool, encoded.len);
    if (encoded.data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64(&encoded, &plain);

    final.len = sizeof("Basic ") + encoded.len - 1;
    final.data = ngx_pnalloc(r->pool, final.len);
    if (final.data == NULL) {
        return NGX_ERROR;
    }

    ngx_snprintf(final.data, final.len, "Basic %V", &encoded);

    /* Set or clobber the Authorization header so that nginx's $remote_user
     * machinery (ngx_http_auth_basic_user) can parse the username from it.
     * Cookie-only requests have no Authorization header; create one. */
    if (r->headers_in.authorization == NULL) {
        ngx_table_elt_t *h = ngx_list_push(&r->headers_in.headers);
        if (h == NULL)
            return NGX_ERROR;
        h->hash = 1;
#if defined(nginx_version) && nginx_version >= 1023000
        h->next = NULL;
#endif
        h->key.len  = sizeof("Authorization") - 1;
        h->key.data = (u_char *)"Authorization";
        r->headers_in.authorization = h;
    }
    r->headers_in.authorization->value.len  = final.len;
    r->headers_in.authorization->value.data = final.data;

    spnego_debug0(
        "ngx_http_auth_spnego_set_bogus_authorization: bogus user set");
    return NGX_OK;
}


#ifdef NGX_HAVE_CRED_STORE
static void
ngx_http_auth_spnego_release_constrained_creds(void *data) {
    ngx_http_auth_spnego_loc_conf_t *alcf = data;
    OM_uint32 minor_status;
    if (alcf->constrained_creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&minor_status, &alcf->constrained_creds);
}

static ngx_int_t
ngx_http_auth_spnego_ensure_constrained_creds(ngx_http_request_t *r,
    ngx_http_auth_spnego_loc_conf_t *alcf, gss_name_t svc_name)
{
    OM_uint32 major_status, minor_status;
    OM_uint32 lifetime = 0;

    if (alcf->constrained_creds != GSS_C_NO_CREDENTIAL) {
        major_status = gss_inquire_cred(&minor_status, alcf->constrained_creds,
                                        NULL, &lifetime, NULL, NULL);
        if (GSS_ERROR(major_status))
            lifetime = 0;
    }

    if (lifetime < RENEWAL_TIME) {
        gss_cred_id_t old_creds = alcf->constrained_creds;
        gss_key_value_element_desc elements[2];
        gss_key_value_set_desc store;

        elements[0].key   = "keytab";
        elements[0].value = alcf->keytab_prefix_path;
        elements[1].key   = "client_keytab";
        elements[1].value = alcf->keytab_prefix_path;
        store.count    = 2;
        store.elements = elements;

        major_status = gss_acquire_cred_from(
            &minor_status, svc_name, GSS_C_INDEFINITE,
            GSS_C_NO_OID_SET, GSS_C_BOTH, &store,
            &alcf->constrained_creds, NULL, NULL);
        if (GSS_ERROR(major_status)) {
            alcf->constrained_creds = old_creds;
            spnego_log_error("%s Used keytab: %s",
                             get_gss_error(r->pool, major_status, minor_status,
                                           "gss_acquire_cred_from() failed"),
                             alcf->keytab_prefix_path);
            return NGX_ERROR;
        }

        if (old_creds != GSS_C_NO_CREDENTIAL) {
            gss_release_cred(&minor_status, &old_creds);
        } else {
            ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(ngx_cycle->pool, 0);
            if (cln == NULL)
                return NGX_ERROR;
            cln->handler = ngx_http_auth_spnego_release_constrained_creds;
            cln->data    = alcf;
        }
    }

    return NGX_OK;
}
#endif /* NGX_HAVE_CRED_STORE */


#if (NGX_HTTP_SSL)
/*
 * Build a gss_channel_bindings_t for the selected channel binding type.
 *
 * Returns GSS_C_NO_CHANNEL_BINDINGS on error; to be treated as a hard failure.
 */
static gss_channel_bindings_t
ngx_http_auth_spnego_build_channel_binding(ngx_http_request_t *r,
                                            ngx_uint_t type)
{
    SSL                    *ssl = r->connection->ssl->connection;
    gss_channel_bindings_t  cb;
    unsigned char          *app_data;
    size_t                  app_data_len;

    if (type == NGX_HTTP_AUTH_SPNEGO_CB_EXPORTER) {
        static const char  prefix[] = "tls-exporter:";
        unsigned char      exported[32];

        if (SSL_export_keying_material(ssl, exported, sizeof(exported),
                                       "EXPORTER-Channel-Binding",
                                       sizeof("EXPORTER-Channel-Binding") - 1,
                                       NULL, 0, 1) != 1) {
            spnego_log_error("SSL_export_keying_material() failed");
            return GSS_C_NO_CHANNEL_BINDINGS;
        }

        app_data_len = (sizeof(prefix) - 1) + sizeof(exported);
        app_data     = ngx_palloc(r->pool, app_data_len);
        if (app_data == NULL)
            return GSS_C_NO_CHANNEL_BINDINGS;

        u_char *p = ngx_cpymem(app_data, prefix, sizeof(prefix) - 1);
        ngx_memcpy(p, exported, sizeof(exported));

    } else if (type == NGX_HTTP_AUTH_SPNEGO_CB_SERVER_EP) {
        static const char  prefix[]    = "tls-server-end-point:";
        X509              *cert;
        const EVP_MD      *md;
        EVP_MD_CTX        *mdctx;
        unsigned char     *der, *der_p;
        unsigned char      hash[EVP_MAX_MD_SIZE];
        unsigned int       hash_len;
        int                der_len, sig_hash_nid;

        cert = SSL_get_certificate(ssl);
        if (cert == NULL)
            return GSS_C_NO_CHANNEL_BINDINGS;

        /* RFC 5929 §4: use cert's sig-hash unless it's MD5/SHA-1 */
        md = EVP_sha256();
        if (OBJ_find_sigid_algs(X509_get_signature_nid(cert),
                                &sig_hash_nid, NULL)
            && sig_hash_nid != NID_md5 && sig_hash_nid != NID_sha1)
        {
            const EVP_MD *candidate = EVP_get_digestbynid(sig_hash_nid);
            if (candidate != NULL)
                md = candidate;
        }

        der_len = i2d_X509(cert, NULL);
        if (der_len <= 0)
            return GSS_C_NO_CHANNEL_BINDINGS;

        der = der_p = ngx_palloc(r->pool, der_len);
        if (der == NULL)
            return GSS_C_NO_CHANNEL_BINDINGS;
        i2d_X509(cert, &der_p);

        mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL)
            return GSS_C_NO_CHANNEL_BINDINGS;
        if (EVP_DigestInit_ex(mdctx, md, NULL) != 1 ||
            EVP_DigestUpdate(mdctx, der, der_len) != 1 ||
            EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
            spnego_log_error("EVP digest failed computing "
                             "tls-server-end-point channel binding");
            EVP_MD_CTX_free(mdctx);
            return GSS_C_NO_CHANNEL_BINDINGS;
        }
        EVP_MD_CTX_free(mdctx);

        app_data_len = (sizeof(prefix) - 1) + hash_len;
        app_data     = ngx_palloc(r->pool, app_data_len);
        if (app_data == NULL)
            return GSS_C_NO_CHANNEL_BINDINGS;

        u_char *p = ngx_cpymem(app_data, prefix, sizeof(prefix) - 1);
        ngx_memcpy(p, hash, hash_len);

    } else {
        return GSS_C_NO_CHANNEL_BINDINGS;
    }

    cb = ngx_pcalloc(r->pool, sizeof(struct gss_channel_bindings_struct));
    if (cb == NULL)
        return GSS_C_NO_CHANNEL_BINDINGS;

    cb->application_data.length = app_data_len;
    cb->application_data.value  = app_data;

    return cb;
}
#endif /* NGX_HTTP_SSL */

ngx_int_t
ngx_http_auth_spnego_auth_user_gss(ngx_http_request_t *r,
                                   ngx_http_auth_spnego_ctx_t *ctx,
                                   ngx_http_auth_spnego_loc_conf_t *alcf) {
    ngx_int_t ret = NGX_DECLINED;
    ngx_str_t spnego_token = ngx_null_string;
    OM_uint32 major_status, minor_status, ret_flags, time_rec;
    gss_buffer_desc service = GSS_C_EMPTY_BUFFER;
    gss_name_t my_gss_name = GSS_C_NO_NAME;

    gss_cred_id_t my_gss_creds = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t delegated_creds = GSS_C_NO_CREDENTIAL;

    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_channel_bindings_t cb;
    char *gssname = NULL;

    if (ctx == NULL || ctx->token.len == 0)
        return ret;

    spnego_debug0("GSSAPI authorizing");
    spnego_debug1("Use keytab %s", alcf->keytab_path);

    if (alcf->service_principal) {
        service.length = ngx_strlen(alcf->service_principal);
        service.value = alcf->service_principal;

        spnego_debug1("Using service principal: %s", alcf->service_principal);
        major_status = gss_import_name(&minor_status, &service,
                           GSS_C_NO_OID,
                           &my_gss_name);
        if (GSS_ERROR(major_status)) {
            spnego_log_error("%s Used service principal: %s",
                             get_gss_error(r->pool, major_status, minor_status,
                                           "gss_import_name() failed"),
                             alcf->service_principal);
            spnego_error(NGX_ERROR);
        }
    }

#ifdef NGX_HAVE_CRED_STORE
    if ((alcf->delegation & SPNEGO_DELEG_CONSTRAINED) && my_gss_name != GSS_C_NO_NAME) {
        if (ngx_http_auth_spnego_ensure_constrained_creds(r, alcf, my_gss_name) != NGX_OK) {
            spnego_error(NGX_ERROR);
        }
        my_gss_creds = alcf->constrained_creds;
    } else
#endif /* NGX_HAVE_CRED_STORE */
    {
#ifdef NGX_HAVE_GSS_ACQUIRE_CRED_FROM
        gss_key_value_element_desc elements[1];
        gss_key_value_set_desc store;

        elements[0].key   = "keytab";
        elements[0].value = alcf->keytab_prefix_path;
        store.count    = 1;
        store.elements = elements;

        major_status = gss_acquire_cred_from(
            &minor_status, my_gss_name, GSS_C_INDEFINITE,
            GSS_C_NO_OID_SET, GSS_C_ACCEPT, &store, &my_gss_creds, NULL, NULL);
#else
        /* No gss_acquire_cred_from() (Heimdal 7.x): fall back to the default
         * acceptor credential.  See ngx_http_auth_spnego_basic() for notes. */
        major_status = gss_acquire_cred(
            &minor_status, my_gss_name, GSS_C_INDEFINITE,
            GSS_C_NO_OID_SET, GSS_C_ACCEPT, &my_gss_creds, NULL, NULL);
#endif
        if (GSS_ERROR(major_status)) {
            spnego_log_error("%s Used keytab: %s",
                             get_gss_error(r->pool, major_status, minor_status,
                                           "failed to acquire acceptor credential"),
                             alcf->keytab_prefix_path);
            spnego_error(NGX_ERROR);
        }
    }

    input_token.length = ctx->token.len;
    input_token.value = (void *)ctx->token.data;

    cb = GSS_C_NO_CHANNEL_BINDINGS;
    if (alcf->channel_binding != NGX_HTTP_AUTH_SPNEGO_CB_OFF) {
#if (NGX_HTTP_SSL)
        if (r->connection->ssl == NULL) {
            spnego_log_error("auth_gss_channel_binding configured but "
                             "connection is not via TLS");
            spnego_error(NGX_ERROR);
        }
        cb = ngx_http_auth_spnego_build_channel_binding(r, alcf->channel_binding);
        if (cb == GSS_C_NO_CHANNEL_BINDINGS) {
            spnego_log_error("failed to build channel binding");
            spnego_error(NGX_ERROR);
        }
#endif
    }

    time_rec = GSS_C_INDEFINITE;
    major_status = gss_accept_sec_context(
        &minor_status, &gss_context, my_gss_creds, &input_token,
        cb, &client_name, NULL, &output_token,
        &ret_flags, &time_rec, &delegated_creds);

    if (GSS_ERROR(major_status)) {
        spnego_debug1("%s", get_gss_error(r->pool, major_status, minor_status,
                                          "gss_accept_sec_context() failed"));
        spnego_error(NGX_DECLINED);
    }

    if (major_status & GSS_S_CONTINUE_NEEDED) {
        spnego_debug0("only one authentication iteration allowed");
        spnego_error(NGX_DECLINED);
    }

#ifdef NGX_HTTP_AUTH_SPNEGO_HAVE_CB_FLAG
    if (alcf->channel_binding != NGX_HTTP_AUTH_SPNEGO_CB_OFF
        && !(ret_flags & GSS_C_CHANNEL_BOUND_FLAG)) {
        spnego_log_error("channel binding required but not provided by client");
        spnego_error(NGX_DECLINED);
    }
#endif

    if (output_token.length) {
        spnego_token.data = (u_char *)output_token.value;
        spnego_token.len = output_token.length;

        ctx->token_out_b64.len = ngx_base64_encoded_length(spnego_token.len);
        ctx->token_out_b64.data =
            ngx_pcalloc(r->pool, ctx->token_out_b64.len + 1);
        if (ctx->token_out_b64.data == NULL) {
            spnego_log_error("Not enough memory");
            gss_release_buffer(&minor_status, &output_token);
            spnego_error(NGX_ERROR);
        }
        ngx_encode_base64(&ctx->token_out_b64, &spnego_token);
        gss_release_buffer(&minor_status, &output_token);
    } else {
        ctx->token_out_b64.len = 0;
    }

    /* get the authenticated client principal name */
    major_status =
        gss_display_name(&minor_status, client_name, &output_token, NULL);
    if (GSS_ERROR(major_status)) {
        spnego_log_error("%s", get_gss_error(r->pool, major_status, minor_status,
                                             "gss_display_name() failed"));
        spnego_error(NGX_ERROR);
    }

    /* Save full GSS name before map_to_local may replace output_token */
    if (output_token.length > 0) {
        gssname = ngx_pnalloc(r->pool, output_token.length + 1);
        if (gssname != NULL) {
            ngx_memcpy(gssname, output_token.value, output_token.length);
            gssname[output_token.length] = '\0';
        }
    }

    if (output_token.length && alcf->map_to_local) {
        /* Apply local rules to map Kerberos Principals to short names */
        gss_release_buffer(&minor_status, &output_token);
        output_token = (gss_buffer_desc)GSS_C_EMPTY_BUFFER;
        major_status = gss_localname(&minor_status, client_name, GSS_C_NO_OID,
                                     &output_token);
        if (GSS_ERROR(major_status)) {
            spnego_log_error("%s", get_gss_error(r->pool, major_status, minor_status,
                                                 "gss_localname() failed"));
            spnego_error(NGX_DECLINED);
        }
    }

    if (output_token.length) {
        char *username = ngx_pnalloc(r->pool, output_token.length + 1);
        if (username == NULL) {
            spnego_log_error("Not enough memory");
            spnego_error(NGX_ERROR);
        }
        ngx_memcpy(username, output_token.value, output_token.length);
        username[output_token.length] = '\0';

#ifdef NGX_HAVE_CRED_STORE
        if (alcf->delegation != SPNEGO_DELEG_OFF
            && delegated_creds != GSS_C_NO_CREDENTIAL) {
            if (ngx_http_auth_spnego_store_delegated_creds(r, username,
                                                           delegated_creds,
                                                           (char *)alcf->deleg_ccache_dir.data) != NGX_OK) {
                spnego_error(NGX_ERROR);
            }
        }
#endif

        r->headers_in.user.data = (u_char *)username;
        r->headers_in.user.len = output_token.length;
        ngx_http_auth_spnego_strip_realm(r, alcf);

        /* needed for ngx_http_variable_remote_user */
        if (ngx_http_auth_spnego_set_bogus_authorization(r) != NGX_OK) {
            spnego_log_error("Failed to set remote_user");
        }
        spnego_debug1("user is %V", &r->headers_in.user);
    }


#if (NGX_HTTP_SSL)
    ngx_http_auth_spnego_set_session_cookie(r, ctx, alcf, time_rec,
        gssname, NULL);
#endif

    gss_release_buffer(&minor_status, &output_token);
    output_token = (gss_buffer_desc)GSS_C_EMPTY_BUFFER;

    {
        ngx_str_t at_var = ngx_string(AUTH_TYPE_VARIABLE_NAME);
        ngx_str_t at_val = ngx_string("spnego");
        ngx_http_auth_spnego_set_variable(r, &at_var, &at_val);
    }

    ret = NGX_OK;
    goto end;

end:
    if (output_token.length)
        gss_release_buffer(&minor_status, &output_token);

    if (client_name != GSS_C_NO_NAME)
        gss_release_name(&minor_status, &client_name);

    if (gss_context != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&minor_status, &gss_context, GSS_C_NO_BUFFER);

    if (my_gss_name != GSS_C_NO_NAME)
        gss_release_name(&minor_status, &my_gss_name);

    if (my_gss_creds != GSS_C_NO_CREDENTIAL
#ifdef NGX_HAVE_CRED_STORE
        && my_gss_creds != alcf->constrained_creds
#endif
        )
        gss_release_cred(&minor_status, &my_gss_creds);

    if (delegated_creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&minor_status, &delegated_creds);

    return ret;
}


static bool
ngx_http_auth_spnego_same_string(ngx_str_t *a, ngx_str_t *b) {
    if (a->len != b->len) {
        return false;
    }
    if (a->len == 0) {
        return true;
    }
    if (ngx_strncmp(a->data, b->data, a->len) != 0) {
        return false;
    }
    return true;
}


/*
 * Given the location of the saved login a and the destination b, reusing
 * the login requires the same values for every setting the login path reads:
 * 1. The same username handling (realm formatting and local name mapping).
 * 2. The same authentication requirements (realm, keytab, service principal,
 *    and channel binding).
 * 3. The same credential delegation settings, including the service
 *    credential cache path when constrained delegation is enabled.
 * 4. Basic allowed at b when the saved login was a Basic login.
 *
 * Different settings get b's normal challenge instead of a check of the
 * bogus basic auth header.
 */
static bool
ngx_http_auth_spnego_same_auth(ngx_http_auth_spnego_ctx_t *ctx,
                               ngx_http_auth_spnego_loc_conf_t *b) {
    ngx_http_auth_spnego_loc_conf_t *a = ctx->alcf;

    if (a->fqun               != b->fqun
        || a->force_realm     != b->force_realm
        || a->map_to_local    != b->map_to_local
        || !ngx_http_auth_spnego_same_string(&a->realm, &b->realm)
        || !ngx_http_auth_spnego_same_string(&a->keytab, &b->keytab)
        || a->channel_binding != b->channel_binding
        || a->delegation      != b->delegation) {
        return false;
    }

    /* An empty token marks a Basic login, which needs Basic allowed at b. */
    if (ctx->token.len == 0 && !b->allow_basic) {
        return false;
    }

#ifdef NGX_HAVE_CRED_STORE
    if (a->delegation & SPNEGO_DELEG_CONSTRAINED) {
        if (!ngx_http_auth_spnego_same_string(&a->deleg_ccache_dir,
                                              &b->deleg_ccache_dir)) {
            return false;
        }
    }
#endif

    if (a->service_principal == b->service_principal) {
        return true;
    }
    if (a->service_principal == NULL || b->service_principal == NULL) {
        return false;
    }
    if (ngx_strcmp(a->service_principal, b->service_principal) != 0) {
        return false;
    }
    return true;
}


/*
 * Whether the authorization header still holds the value it had right after
 * the saved login. Another module may have changed or removed it since.
 * Compare the content with a copy, not the data pointer: a module can
 * change the bytes in place or set the length to 0 while the pointer stays
 * the same, and the saved login would then be reused for credentials it
 * never checked.
 */
static bool
ngx_http_auth_spnego_same_authorization(ngx_http_request_t *r,
                                        ngx_http_auth_spnego_ctx_t *ctx) {
    ngx_table_elt_t *h = r->headers_in.authorization;

    if (h == NULL || (h->value.len != ctx->authorization_set.len)) {
        return false;
    }
    if (ngx_memcmp(h->value.data, ctx->authorization_set.data,
                   h->value.len) != 0) {
        return false;
    }
    return true;
}


/* Remove the saved login's challenge. ngx_http_auth_spnego_restore_login
 * decides whether to keep it for a retained 401. nginx can reuse a header
 * list entry after clearing headers, so both the name and saved value must
 * match before suppressing it. */
static void
ngx_http_auth_spnego_clear_challenge(ngx_http_request_t *r,
                                     ngx_http_auth_spnego_ctx_t *ctx) {
    ngx_table_elt_t *h = ctx->challenge;

    if (h == NULL) {
        return;
    }
    if (h->key.len       == sizeof("WWW-Authenticate") - 1
        && ngx_strncasecmp(h->key.data, (u_char *)"WWW-Authenticate",
                           sizeof("WWW-Authenticate") - 1) == 0
        && h->value.data == ctx->challenge_value.data
        && h->value.len  == ctx->challenge_value.len) {
        h->hash = 0;
        if (r->headers_out.www_authenticate == h) {
#if defined(nginx_version) && nginx_version >= 1023000
            r->headers_out.www_authenticate = h->next;
#else
            r->headers_out.www_authenticate = NULL;
#endif
        }
    }
    ctx->challenge = NULL;
}


/* Changed settings cannot authenticate the saved login's bogus header.
 * Keep the login for a later accepting location, but suppress its username
 * and reply token here. Negotiate challenges bypass nginx's auth_delay,
 * as in the ordinary authentication path. */
static ngx_int_t
ngx_http_auth_spnego_challenge_again(ngx_http_request_t *r,
                                     ngx_http_auth_spnego_ctx_t *ctx,
                                     ngx_http_auth_spnego_loc_conf_t *alcf) {
    ngx_int_t ret;

    ngx_http_auth_spnego_clear_challenge(r, ctx);
    ngx_str_set(&r->headers_in.user, "");
    if (alcf->allow_basic) {
        ret = ngx_http_auth_spnego_headers_basic_only(r, ctx, alcf);
    } else {
        ret = ngx_http_auth_spnego_headers(r, ctx, NULL, alcf);
    }
    if (ret == NGX_ERROR) {
        return (ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    ctx->challenge = r->headers_out.www_authenticate;
    ctx->challenge_value = ctx->challenge->value;
    if (alcf->allow_basic) {
        return (ctx->ret = NGX_HTTP_UNAUTHORIZED);
    }
    ctx->ret = NGX_DONE;
    ngx_http_finalize_request(r, NGX_HTTP_UNAUTHORIZED);
    return NGX_DONE;
}


/* A saved login survives a refusal so an error_page destination can accept
 * it. Its result must still describe this location, to withhold credentials
 * and the reply token when this location refuses access. */
static ngx_int_t
ngx_http_auth_spnego_reuse_login(ngx_http_request_t *r,
                                 ngx_http_auth_spnego_ctx_t *ctx,
                                 ngx_http_auth_spnego_loc_conf_t *alcf) {
    if (!ngx_http_auth_spnego_same_auth(ctx, alcf)) {
        spnego_debug0("Authenticated under a different configuration");
        return ngx_http_auth_spnego_challenge_again(r, ctx, alcf);
    }

    r->headers_in.user = ctx->user;
    if (!ngx_spnego_authorized_principal(r, &r->headers_in.user, alcf)) {
        spnego_debug0("User not authorized");
        return (ctx->ret = NGX_HTTP_FORBIDDEN);
    }
    ctx->head = 0;
    ctx->uri_changes = r->uri_changes;
    spnego_debug0("Already authenticated");
    return (ctx->ret = NGX_OK);
}


/* Record a login in the request pool because nginx clears module contexts
 * on an internal redirect. Copy the header bytes so changes made in place
 * are detected too. Publish the marker only after both allocations succeed. */
static ngx_int_t
ngx_http_auth_spnego_save_login(ngx_http_request_t *r,
                                ngx_http_auth_spnego_ctx_t *ctx,
                                ngx_http_auth_spnego_loc_conf_t *alcf) {
    ngx_pool_cleanup_t *cln;
    ngx_str_t authorization_set;

    authorization_set = r->headers_in.authorization->value;
    authorization_set.data = ngx_pstrdup(r->pool, &authorization_set);
    if (authorization_set.data == NULL) {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }
    ctx->user = r->headers_in.user;
    ctx->authorization_set = authorization_set;
    ctx->alcf = alcf;
    ctx->uri_changes = r->uri_changes;
    cln->data = ctx;
    cln->handler = ngx_http_auth_spnego_cleanup;
    return NGX_OK;
}


/* Save before authorization so an error_page after a 403 can reuse the
 * login. The caller keeps the refusal as this location's result. */
static ngx_int_t
ngx_http_auth_spnego_save_and_authorize(ngx_http_request_t *r,
                                        ngx_http_auth_spnego_ctx_t *ctx,
                                        ngx_http_auth_spnego_loc_conf_t *alcf) {
    if (ngx_http_auth_spnego_save_login(r, ctx, alcf) != NGX_OK) {
        return (ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    if (!ngx_spnego_authorized_principal(r, &r->headers_in.user,
                                         alcf)) {
        spnego_debug0("User not authorized");
        return (ctx->ret = NGX_HTTP_FORBIDDEN);
    }
    return NGX_OK;
}


/* Basic credentials get their own result, including a Basic only challenge
 * on failure. They must not continue into Negotiate authentication. */
static ngx_int_t
ngx_http_auth_spnego_basic_handler(ngx_http_request_t *r,
                                   ngx_http_auth_spnego_ctx_t *ctx,
                                   ngx_http_auth_spnego_loc_conf_t *alcf) {
    ngx_int_t ret = ngx_http_auth_spnego_basic(r, ctx, alcf);
    if (ret == NGX_ERROR) {
        return (ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    if (ret != NGX_OK) {
        spnego_debug0("Basic auth failed");
        if (ngx_http_auth_spnego_headers_basic_only(r, ctx, alcf) ==
            NGX_ERROR) {
            spnego_debug0("Error setting headers");
            return (ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR);
        }

        return (ctx->ret = NGX_HTTP_UNAUTHORIZED);
    }

    if (ngx_http_auth_spnego_save_and_authorize(r, ctx, alcf) != NGX_OK) {
        return ctx->ret;
    }
    spnego_debug0("Basic auth succeeded");
    return (ctx->ret = NGX_OK);
}


/* Keep authentication failure separate from an absent Negotiate token:
 * only a supplied token can produce a Basic only challenge here. */
static ngx_int_t
ngx_http_auth_spnego_gss_handler(ngx_http_request_t *r,
                                 ngx_http_auth_spnego_ctx_t *ctx,
                                 ngx_http_auth_spnego_loc_conf_t *alcf) {
    ngx_int_t ret;

    spnego_debug0("Client sent a reasonable Negotiate header");
    ret = ngx_http_auth_spnego_auth_user_gss(r, ctx, alcf);
    if (ret == NGX_ERROR) {
        spnego_debug0("GSSAPI failed");
        return (ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    if (ret == NGX_DECLINED) {
        spnego_debug0("GSSAPI failed");
        if (!alcf->allow_basic) {
            return (ctx->ret = NGX_HTTP_FORBIDDEN);
        }
        if (ngx_http_auth_spnego_headers_basic_only(r, ctx, alcf) ==
            NGX_ERROR) {
            spnego_debug0("Error setting headers");
            return (ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        /* finalize directly to bypass core auth_delay (not a credential failure) */
        ctx->ret = NGX_DONE;
        ngx_http_finalize_request(r, NGX_HTTP_UNAUTHORIZED);
        return NGX_DONE;
    }

    if (ngx_http_auth_spnego_save_and_authorize(r, ctx, alcf) != NGX_OK) {
        return ctx->ret;
    }
    spnego_debug0("GSSAPI auth succeeded");
    return ret;
}


static ngx_int_t
ngx_http_auth_spnego_negotiate(ngx_http_request_t *r,
                               ngx_http_auth_spnego_ctx_t *ctx,
                               ngx_http_auth_spnego_loc_conf_t *alcf) {
    ngx_int_t ret;

    /* Basic auth either disabled or not supplied by client */
    spnego_debug0("Detect SPNEGO token");
    ret = ngx_http_auth_spnego_token(r, ctx);
    if (ret == NGX_OK) {
        ret = ngx_http_auth_spnego_gss_handler(r, ctx, alcf);
        if (ret != NGX_OK) {
            return ret;
        }
    }

    switch (ret) {
    case NGX_DECLINED: /* DECLINED, but not yet FORBIDDEN */
        if (ngx_http_auth_spnego_headers(r, ctx, NULL, alcf) == NGX_ERROR) {
            spnego_debug0("Error setting headers");
            ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR;
        } else {
            /* finalize directly to bypass core auth_delay (not a credential failure) */
            ctx->ret = NGX_DONE;
            ngx_http_finalize_request(r, NGX_HTTP_UNAUTHORIZED);
            return NGX_DONE;
        }
        break;
    case NGX_OK:
        ctx->ret = NGX_OK;
        /* WWW-Authenticate: Negotiate <token> is emitted by the output header
         * filter, which runs after nginx's satisfy-any WWW-Authenticate
         * cleanup, so the mutual-auth token survives satisfy any. */
        break;
    case NGX_ERROR:
    default:
        ctx->ret = NGX_HTTP_INTERNAL_SERVER_ERROR;
        break;
    }

    spnego_debug3("SSO auth handling OUT: token.len=%d, head=%d, ret=%d",
                  ctx->token.len, ctx->head, ctx->ret);
    return ctx->ret;
}


static ngx_int_t
ngx_http_auth_spnego_authenticate(ngx_http_request_t *r,
                                  ngx_http_auth_spnego_ctx_t *ctx,
                                  ngx_http_auth_spnego_loc_conf_t *alcf,
                                  bool allow_basic) {
    ngx_int_t ret = NGX_DECLINED;

    spnego_debug3("SSO auth handling IN: token.len=%d, head=%d, ret=%d",
                  ctx->token.len, ctx->head, ctx->ret);

    if (ctx->token.len && ctx->head) {
        spnego_debug1("Found token and head, returning %d", ctx->ret);
        return ctx->ret;
    }
    if (ctx->ret == NGX_OK) {
        spnego_debug0("Already authenticated");
        return NGX_OK;
    }
#if (NGX_HTTP_SSL)
    /* Session cookie check: if a valid encrypted cookie is present, accept it
     * without SPNEGO.  The cookie contains the verified principal name and an
     * expiry timestamp protected by AES-256-GCM. */
    if (alcf->session_key_loaded && alcf->session_expiry > 0) {
        ngx_str_t cookie_val = ngx_http_auth_spnego_find_cookie(
            r, &alcf->session_cookie_name);
        if (cookie_val.len > 0) {
            ngx_http_auth_spnego_session_t *sess =
                ngx_http_auth_spnego_decrypt_session(
                    r->pool, alcf->session_enc_key, alcf->session_cipher,
                    alcf->session_aad, alcf->session_aad_len,
                    &cookie_val);
            if (sess != NULL && sess->has_basichash) {
                /* Cookie was minted from a Basic Auth login.  Require the
                 * client to keep presenting Basic credentials and verify
                 * they still hash to the value baked into the cookie.
                 * Matches mod_auth_gssapi's stance for Basic-derived
                 * sessions (mod_auth_gssapi.c:1092-1100: cookie-only
                 * acceptance excludes AUTH_TYPE_BASIC), closing the bare
                 * stolen-cookie replay window for the Basic path.
                 * SPNEGO-issued cookies have has_basichash=0 and bypass
                 * this gate entirely. */
                if (ngx_http_auth_basic_user(r) != NGX_OK) {
                    spnego_debug0("Basic-derived session cookie without "
                                  "Basic credentials; rejecting");
                    sess = NULL;
                } else if (r->headers_in.user.len != ngx_strlen(sess->username)
                           || ngx_strncmp(r->headers_in.user.data,
                                          sess->username,
                                          r->headers_in.user.len) != 0) {
                    spnego_debug0("Session cookie username mismatch");
                    sess = NULL;
                } else {
                    uint8_t mac[32];
                    bool hmac_ok =
                        ngx_http_auth_spnego_session_hmac(
                            r->pool, alcf->session_mac_key,
                            alcf->session_mac,
                            (u_char *)sess->username,
                            ngx_strlen(sess->username),
                            r->headers_in.passwd.data,
                            r->headers_in.passwd.len,
                            mac) == NGX_OK
                        && CRYPTO_memcmp(mac, sess->basichash, 32) == 0;
                    ngx_explicit_memzero(mac, sizeof(mac));
                    if (!hmac_ok) {
                        spnego_debug0("Session cookie basichash mismatch");
                        sess = NULL;
                    }
                }
            }
            if (sess != NULL) {
                spnego_debug1("Session cookie valid for %s", sess->username);

                /* Set $krb5_session_principal from the stored full GSS name */
                ngx_str_t sp_var   = ngx_string(SESSION_PRINCIPAL_VARIABLE_NAME);
                ngx_str_t sp_value = { ngx_strlen(sess->gssname),
                                       (u_char *)sess->gssname };
                ngx_http_auth_spnego_set_variable(r, &sp_var, &sp_value);

                /* Set $krb5_cc_name from the stored ccache path */
                if (sess->ccname != NULL && sess->ccname[0] != '\0') {
                    ngx_str_t cc_var   = ngx_string(CCACHE_VARIABLE_NAME);
                    ngx_str_t cc_value = { ngx_strlen(sess->ccname),
                                           (u_char *)sess->ccname };
                    ngx_http_auth_spnego_set_variable(r, &cc_var, &cc_value);
                }

                /* Set $remote_user and accept the request */
                r->headers_in.user.data = (u_char *)sess->username;
                r->headers_in.user.len  = ngx_strlen(sess->username);

                if (!ngx_spnego_authorized_principal(r, &r->headers_in.user,
                                                     alcf)) {
                    spnego_debug1("Session cookie principal not authorized: \"%V\"",
                                 &r->headers_in.user);
                    return (ctx->ret = NGX_HTTP_FORBIDDEN);
                }

                if (ngx_http_auth_spnego_set_bogus_authorization(r) != NGX_OK) {
                    spnego_log_error("Failed to set remote_user from session");
                } else if (ngx_http_auth_spnego_save_login(r, ctx, alcf)
                           != NGX_OK) {
                    spnego_log_error("Failed to save cookie login for redirect");
                }

                spnego_debug1("Session cookie auth succeeded for %s",
                              sess->username);

                {
                    ngx_str_t at_var = ngx_string(AUTH_TYPE_VARIABLE_NAME);
                    ngx_str_t at_val = ngx_string("cookie");
                    ngx_http_auth_spnego_set_variable(r, &at_var, &at_val);
                }

                return (ctx->ret = NGX_OK);
            }
            spnego_debug0("Session cookie present but invalid/expired");
        }
    }
#endif /* NGX_HTTP_SSL */
    spnego_debug0("Begin auth");

    if (allow_basic) {
        spnego_debug0("Detect basic auth");
        ret = ngx_http_auth_basic_user(r);
        if (ret == NGX_OK) {
            spnego_debug0("Basic auth credentials supplied by client");
            /* If basic auth is enabled and basic creds are supplied
             * attempt basic auth.  If we attempt basic auth, we do
             * not fall through to real SPNEGO */
            return ngx_http_auth_spnego_basic_handler(r, ctx, alcf);
        }
    }
    return ngx_http_auth_spnego_negotiate(r, ctx, alcf);
}


/* A fresh attempt preserves any username parsed before this module ran,
 * as on a direct request. Discarding a saved login clears it separately. */
static ngx_http_auth_spnego_ctx_t *
ngx_http_auth_spnego_new_ctx(ngx_http_request_t *r) {
    ngx_http_auth_spnego_ctx_t *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_spnego_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->ret = NGX_HTTP_UNAUTHORIZED;
    ngx_http_set_ctx(r, ctx, ngx_http_auth_spnego_module);
    return ctx;
}


/* A changed header discards the saved login permanently. It still provides
 * credentials to public destinations through ngx_http_auth_spnego_saved_ccache.
 * If the header was removed, skip Basic parsing on this attempt: nginx's
 * "no user" mark would prevent a later replacement header from being parsed
 * after another redirect. */
static ngx_int_t
ngx_http_auth_spnego_restore_login(ngx_http_request_t *r,
                                   ngx_http_auth_spnego_ctx_t *ctx,
                                   ngx_http_auth_spnego_loc_conf_t *alcf) {
    if (r->err_status != NGX_HTTP_UNAUTHORIZED) {
        ngx_http_auth_spnego_clear_challenge(r, ctx);
    }
    ctx->redirected = 1;
    ctx->ret = NGX_HTTP_UNAUTHORIZED;
    if (ngx_http_auth_spnego_same_authorization(r, ctx)) {
        ngx_http_set_ctx(r, ctx, ngx_http_auth_spnego_module);
        return ngx_http_auth_spnego_reuse_login(r, ctx, alcf);
    }

    spnego_debug0("Authorization header changed after login");
    ctx->alcf = NULL;
    ngx_str_null(&r->headers_in.user);
    ngx_str_null(&r->headers_in.passwd);
    ctx = ngx_http_auth_spnego_new_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (r->headers_in.authorization == NULL) {
        return ngx_http_auth_spnego_authenticate(r, ctx, alcf, false);
    }
    return ngx_http_auth_spnego_authenticate(r, ctx, alcf, alcf->allow_basic);
}


static ngx_int_t ngx_http_auth_spnego_handler(ngx_http_request_t *r) {
    ngx_http_auth_spnego_ctx_t *ctx;
    ngx_http_auth_spnego_loc_conf_t *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_spnego_module);

    if (alcf->protect == 0) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_spnego_module);
    if (ctx == NULL) {
        ctx = ngx_http_auth_spnego_get_ctx(r);
        if (ctx != NULL) {
            return ngx_http_auth_spnego_restore_login(r, ctx, alcf);
        }
        ctx = ngx_http_auth_spnego_new_ctx(r);
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    return ngx_http_auth_spnego_authenticate(r, ctx, alcf, alcf->allow_basic);
}
