/* ===----------------------------------------------------------------------===
 * Copyright (c) 2026 the grpc-mojo contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 * ===----------------------------------------------------------------------===
 *
 * Thin C wrapper over libssl for mojo-tls.
 *
 * Exists for one structural reason: OpenSSL's server-side ALPN selection
 * happens through a C callback, which Mojo cannot provide. The callback
 * lives here (selecting from a protocol list stored on the context), and
 * while we are at it the handful of context/handshake/read/write entry
 * points are flattened into a plain function surface that is pleasant to
 * call through dlopen/dlsym.
 *
 * Conventions: every function is prefixed mts_; handles are opaque
 * pointers returned as void*; functions returning int use >= 0 for
 * success and negative values for failure (read/write return the
 * negated SSL_get_error class so the caller can distinguish clean TLS
 * EOF, syscall errors, and protocol errors).
 */

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    SSL_CTX *ctx;
    unsigned char alpn_wire[256];
    int alpn_len;
    atomic_int refs;
} mts_ctx;

typedef struct {
    SSL *ssl;
    mts_ctx *config;
} mts_ssl;

/* Server-side ALPN selection: pick the first protocol from our stored
 * list that the client offered. Fatal alert on no overlap, per RFC 7301. */
static int mts_alpn_select(SSL *ssl, const unsigned char **out,
                           unsigned char *outlen, const unsigned char *in,
                           unsigned int inlen, void *arg) {
    (void)ssl;
    mts_ctx *c = (mts_ctx *)arg;
    if (SSL_select_next_proto((unsigned char **)out, outlen, c->alpn_wire,
                              (unsigned int)c->alpn_len, in,
                              inlen) == OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

void *mts_ctx_new_client(void) {
    mts_ctx *c = calloc(1, sizeof(mts_ctx));
    if (!c) return NULL;
    c->ctx = SSL_CTX_new(TLS_client_method());
    if (!c->ctx) {
        free(c);
        return NULL;
    }
    atomic_init(&c->refs, 1);
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
    return c;
}

void *mts_ctx_new_server(const char *cert_chain_pem, const char *key_pem) {
    mts_ctx *c = calloc(1, sizeof(mts_ctx));
    if (!c) return NULL;
    c->ctx = SSL_CTX_new(TLS_server_method());
    if (!c->ctx) {
        free(c);
        return NULL;
    }
    atomic_init(&c->refs, 1);
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_chain_file(c->ctx, cert_chain_pem) != 1 ||
        SSL_CTX_use_PrivateKey_file(c->ctx, key_pem, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(c->ctx) != 1) {
        SSL_CTX_free(c->ctx);
        free(c);
        return NULL;
    }
    return c;
}

int mts_ctx_load_ca(void *p, const char *ca_pem_path) {
    return SSL_CTX_load_verify_locations(((mts_ctx *)p)->ctx, ca_pem_path,
                                         NULL) == 1
               ? 0
               : -1;
}

int mts_ctx_load_default_ca(void *p) {
    return SSL_CTX_set_default_verify_paths(((mts_ctx *)p)->ctx) == 1 ? 0 : -1;
}

void mts_ctx_set_verify(void *p, int enabled) {
    SSL_CTX *ctx = ((mts_ctx *)p)->ctx;
    SSL_CTX_set_verify(ctx, enabled ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                       NULL);
    if (enabled) {
        /* Match modern CPython (3.13+): strict X.509 checks, so a CA
         * without the proper basicConstraints/keyUsage extensions is
         * rejected the same way the reference implementation rejects
         * it. */
        X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(ctx),
                                    X509_V_FLAG_X509_STRICT);
    }
}

/* wire is the ALPN wire format: length-prefixed protocol names, e.g.
 * "\x02h2\x08http/1.1". Configures both directions: the client offer and
 * the server selection callback. */
int mts_ctx_set_alpn(void *p, const unsigned char *wire, int len) {
    mts_ctx *c = (mts_ctx *)p;
    if (len <= 0 || len > (int)sizeof(c->alpn_wire)) return -1;
    memcpy(c->alpn_wire, wire, (size_t)len);
    c->alpn_len = len;
    /* Note: this call returns 0 on success, unlike most of libssl. */
    if (SSL_CTX_set_alpn_protos(c->ctx, wire, (unsigned int)len) != 0)
        return -1;
    SSL_CTX_set_alpn_select_cb(c->ctx, mts_alpn_select, c);
    return 0;
}

static void mts_ctx_release(mts_ctx *c) {
    if (!c) return;
    if (atomic_fetch_sub_explicit(&c->refs, 1, memory_order_acq_rel) != 1)
        return;
    SSL_CTX_free(c->ctx);
    free(c);
}

void mts_ctx_free(void *p) {
    mts_ctx *c = (mts_ctx *)p;
    mts_ctx_release(c);
}

void *mts_ssl_new(void *p, int fd) {
    mts_ctx *c = (mts_ctx *)p;
    mts_ssl *s = calloc(1, sizeof(mts_ssl));
    if (!s) return NULL;
    s->ssl = SSL_new(c->ctx);
    if (!s->ssl) {
        free(s);
        return NULL;
    }
    s->config = c;
    atomic_fetch_add_explicit(&c->refs, 1, memory_order_relaxed);
    SSL_set_mode(s->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE |
                             SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (SSL_set_fd(s->ssl, fd) != 1) {
        SSL_free(s->ssl);
        mts_ctx_release(c);
        free(s);
        return NULL;
    }
    return s;
}

/* sni also enables RFC 6125 hostname verification against the peer
 * certificate; pass an empty string to skip both. This is separate from
 * SSL_connect because a resumable handshake configures the name once. */
int mts_ssl_set_connect_name(void *s, const char *sni) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    if (sni && sni[0]) {
        if (SSL_set_tlsext_host_name(ssl, sni) != 1) return -1;
        if (SSL_set1_host(ssl, sni) != 1) return -1;
    }
    return 0;
}

/* Handshake calls return 0 on completion or the negated SSL_get_error class.
 * WANT_READ (-2) and WANT_WRITE (-3) are progress states, not failures. */
int mts_ssl_connect(void *s) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    int n = SSL_connect(ssl);
    return n == 1 ? 0 : -SSL_get_error(ssl, n);
}

int mts_ssl_accept(void *s) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    int n = SSL_accept(ssl);
    return n == 1 ? 0 : -SSL_get_error(ssl, n);
}

/* Returns bytes read (> 0), 0 on clean TLS EOF (close_notify), or the
 * negated SSL_get_error class (< 0). */
int mts_ssl_read(void *s, unsigned char *buf, int len) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    int n = SSL_read(ssl, buf, len);
    if (n > 0) return n;
    int e = SSL_get_error(ssl, n);
    if (e == SSL_ERROR_ZERO_RETURN) return 0;
    return -e;
}

/* Returns bytes written (> 0) or the negated SSL_get_error class. */
int mts_ssl_write(void *s, const unsigned char *buf, int len) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    int n = SSL_write(ssl, buf, len);
    if (n > 0) return n;
    return -SSL_get_error(ssl, n);
}

int mts_ssl_wants_read(void *s) {
    return SSL_want_read(((mts_ssl *)s)->ssl);
}

int mts_ssl_wants_write(void *s) {
    return SSL_want_write(((mts_ssl *)s)->ssl);
}

/* Copies the negotiated ALPN protocol into buf; returns its length, or 0
 * when nothing was negotiated. */
int mts_ssl_get_alpn(void *s, unsigned char *buf, int cap) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    const unsigned char *d = NULL;
    unsigned int l = 0;
    SSL_get0_alpn_selected(ssl, &d, &l);
    if (!d || (int)l > cap) return 0;
    memcpy(buf, d, l);
    return (int)l;
}

int mts_ssl_version(void *s, char *buf, int cap) {
    const char *v = SSL_get_version(((mts_ssl *)s)->ssl);
    int l = (int)strlen(v);
    if (l >= cap) l = cap - 1;
    memcpy(buf, v, (size_t)l);
    buf[l] = 0;
    return l;
}

long mts_ssl_verify_result(void *s) {
    return SSL_get_verify_result(((mts_ssl *)s)->ssl);
}

int mts_ssl_shutdown(void *s) {
    return SSL_shutdown(((mts_ssl *)s)->ssl);
}

void mts_ssl_free(void *p) {
    mts_ssl *s = (mts_ssl *)p;
    if (!s) return;
    SSL_free(s->ssl);
    mts_ctx_release(s->config);
    free(s);
}

/* Pops one entry from the thread's OpenSSL error queue into buf. */
int mts_last_error(char *buf, int cap) {
    unsigned long e = ERR_get_error();
    if (!e) {
        if (cap > 0) buf[0] = 0;
        return 0;
    }
    ERR_error_string_n(e, buf, (size_t)cap);
    return (int)strlen(buf);
}
