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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <pthread.h>
#include <signal.h>
#include <time.h>
#endif

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

#define MTS_MAX_PEER_CERT_DER (1024 * 1024)
#define MTS_MAX_PEER_NAME 4096
#define MTS_MAX_PEER_SAN_COUNT 256
#define MTS_MAX_PEER_SAN_BYTES (64 * 1024)
#define MTS_MAX_PEER_SAN_VALUE 4096

#define MTS_SAN_DNS 1
#define MTS_SAN_URI 2
#define MTS_SAN_EMAIL 3
#define MTS_SAN_IP 4

/* OpenSSL's socket BIO uses write(2), so a peer reset can raise SIGPIPE on
 * Linux before libssl returns SSL_ERROR_SYSCALL. Block the signal only on
 * the calling thread and consume it only when this operation created it.
 * This preserves the application's process-wide signal policy. */
#ifdef __linux__
typedef struct {
    sigset_t blocked;
    sigset_t previous_mask;
    int active;
    int was_pending;
} mts_sigpipe_guard;

static int mts_sigpipe_guard_begin(mts_sigpipe_guard *guard) {
    memset(guard, 0, sizeof(*guard));
    sigemptyset(&guard->blocked);
    sigaddset(&guard->blocked, SIGPIPE);

    int error = pthread_sigmask(SIG_BLOCK, &guard->blocked,
                                &guard->previous_mask);
    if (error != 0) {
        errno = error;
        return -1;
    }
    guard->active = 1;

    sigset_t pending;
    if (sigpending(&pending) != 0) {
        error = errno;
        pthread_sigmask(SIG_SETMASK, &guard->previous_mask, NULL);
        guard->active = 0;
        errno = error;
        return -1;
    }
    guard->was_pending = sigismember(&pending, SIGPIPE) == 1;
    return 0;
}

static void mts_sigpipe_guard_end(mts_sigpipe_guard *guard, int io_errno) {
    if (!guard->active) return;

    if (io_errno == EPIPE && !guard->was_pending) {
        struct timespec no_wait = {0, 0};
        (void)sigtimedwait(&guard->blocked, NULL, &no_wait);
    }
    (void)pthread_sigmask(SIG_SETMASK, &guard->previous_mask, NULL);
    guard->active = 0;
    errno = io_errno;
}
#else
typedef struct {
    int unused;
} mts_sigpipe_guard;

static int mts_sigpipe_guard_begin(mts_sigpipe_guard *guard) {
    (void)guard;
    return 0;
}

static void mts_sigpipe_guard_end(mts_sigpipe_guard *guard, int io_errno) {
    (void)guard;
    errno = io_errno;
}
#endif

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
    /* Resume with a ticket only. Early application data stays off. */
    SSL_CTX_set_session_cache_mode(c->ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_set_max_early_data(c->ctx, 0);
    return c;
}

/* Library callers cannot answer an interactive PEM password prompt. Refuse
 * encrypted keys now. A future passphrase API can replace this callback with
 * one that copies an explicit caller-owned secret. */
static int mts_reject_password(char *buf, int size, int rwflag,
                               void *userdata) {
    (void)rwflag;
    (void)userdata;
    if (buf && size > 0) buf[0] = '\0';
    return 0;
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
    SSL_CTX_set_session_cache_mode(c->ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_max_early_data(c->ctx, 0);
    SSL_CTX_set_default_passwd_cb(c->ctx, mts_reject_password);
    SSL_CTX_set_default_passwd_cb_userdata(c->ctx, NULL);
    /* OpenSSL refuses to cache or resume server sessions without this. */
    {
        static const unsigned char sid_ctx[] = "mojo-tls";
        if (SSL_CTX_set_session_id_context(
                c->ctx, sid_ctx, (unsigned int)(sizeof(sid_ctx) - 1)) != 1) {
            SSL_CTX_free(c->ctx);
            free(c);
            return NULL;
        }
    }
    if (SSL_CTX_use_certificate_chain_file(c->ctx, cert_chain_pem) != 1 ||
        SSL_CTX_use_PrivateKey_file(c->ctx, key_pem, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(c->ctx) != 1) {
        SSL_CTX_free(c->ctx);
        free(c);
        return NULL;
    }
    return c;
}

int mts_ctx_load_identity(void *p, const char *cert_chain_pem,
                          const char *key_pem) {
    mts_ctx *c = (mts_ctx *)p;
    ERR_clear_error();
    SSL_CTX_set_default_passwd_cb(c->ctx, mts_reject_password);
    SSL_CTX_set_default_passwd_cb_userdata(c->ctx, NULL);
    if (SSL_CTX_use_certificate_chain_file(c->ctx, cert_chain_pem) != 1)
        return -1;
    if (SSL_CTX_use_PrivateKey_file(c->ctx, key_pem, SSL_FILETYPE_PEM) != 1)
        return -1;
    if (SSL_CTX_check_private_key(c->ctx) != 1) return -1;
    ERR_clear_error();
    return 0;
}

int mts_ctx_load_ca(void *p, const char *ca_pem_path) {
    return SSL_CTX_load_verify_locations(((mts_ctx *)p)->ctx, ca_pem_path,
                                         NULL) == 1
               ? 0
               : -1;
}

int mts_ctx_require_client_cert(void *p, const char *ca_pem_path) {
    mts_ctx *c = (mts_ctx *)p;
    ERR_clear_error();
    if (SSL_CTX_load_verify_locations(c->ctx, ca_pem_path, NULL) != 1)
        return -1;

    STACK_OF(X509_NAME) *ca_names = SSL_load_client_CA_file(ca_pem_path);
    if (!ca_names) return -1;
    if (X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(c->ctx),
                                    X509_V_FLAG_X509_STRICT) != 1) {
        sk_X509_NAME_pop_free(ca_names, X509_NAME_free);
        return -1;
    }

    /* SSL_CTX takes ownership of the advertised acceptable CA names. */
    SSL_CTX_set_client_CA_list(c->ctx, ca_names);
    SSL_CTX_set_verify(c->ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);
    ERR_clear_error();
    return 0;
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
 * SSL_connect because a nonblocking handshake configures the name once. */
int mts_ssl_set_connect_name(void *s, const char *sni) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    if (sni && sni[0]) {
        struct in_addr v4;
        struct in6_addr v6;
        if (inet_pton(AF_INET, sni, &v4) == 1 ||
            inet_pton(AF_INET6, sni, &v6) == 1) {
            /* RFC 6066: SNI is a DNS name. Verify IP SANs instead. */
            if (SSL_set1_ip_asc(ssl, sni) != 1) return -1;
            return 0;
        }
        if (SSL_set_tlsext_host_name(ssl, sni) != 1) return -1;
        if (SSL_set1_host(ssl, sni) != 1) return -1;
    }
    return 0;
}

/* SSL_get_error requires the thread error queue to be empty before the I/O
 * call it classifies. Handshake calls return 0 on completion or the negated
 * error class. WANT_READ (-2) and WANT_WRITE (-3) are progress states. */
int mts_ssl_connect(void *s) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    mts_sigpipe_guard guard;
    if (mts_sigpipe_guard_begin(&guard) != 0) return -SSL_ERROR_SYSCALL;
    ERR_clear_error();
    errno = 0;
    int n = SSL_connect(ssl);
    int io_errno = errno;
    int result = n == 1 ? 0 : -SSL_get_error(ssl, n);
    mts_sigpipe_guard_end(&guard, io_errno);
    return result;
}

/* TLS 1.3 can report SSL_connect success before a post-handshake alert
 * (rejected client certificate) is processed. Peek without blocking. When
 * this session presented a client certificate on a blocking socket, wait
 * briefly for POLLIN so that alert is not missed. */
int mts_ssl_confirm_connect(void *s) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    int fd = SSL_get_fd(ssl);
    if (fd < 0) return -SSL_ERROR_SYSCALL;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -SSL_ERROR_SYSCALL;
    int blocking = (flags & O_NONBLOCK) == 0;
    int wait_for_alert = blocking && SSL_get_certificate(ssl) != NULL;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -SSL_ERROR_SYSCALL;

    unsigned char buf[1];
    int result = 0;
    int attempts = wait_for_alert ? 2 : 1;
    int i;
    for (i = 0; i < attempts; i++) {
        if (i == 1) {
            struct pollfd pfd;
            memset(&pfd, 0, sizeof(pfd));
            pfd.fd = fd;
            pfd.events = POLLIN | POLLERR | POLLHUP;
            int pr = poll(&pfd, 1, 50);
            if (pr <= 0) break;
        }
        mts_sigpipe_guard guard;
        if (mts_sigpipe_guard_begin(&guard) != 0) {
            result = -SSL_ERROR_SYSCALL;
            break;
        }
        ERR_clear_error();
        errno = 0;
        int n = SSL_peek(ssl, buf, 1);
        int io_errno = errno;
        if (n > 0) {
            result = 0;
            mts_sigpipe_guard_end(&guard, io_errno);
            break;
        }
        int error = SSL_get_error(ssl, n);
        mts_sigpipe_guard_end(&guard, io_errno);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            result = 0;
            continue;
        }
        result = -error;
        break;
    }
    (void)fcntl(fd, F_SETFL, flags);
    return result;
}

int mts_ssl_accept(void *s) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    mts_sigpipe_guard guard;
    if (mts_sigpipe_guard_begin(&guard) != 0) return -SSL_ERROR_SYSCALL;
    ERR_clear_error();
    errno = 0;
    int n = SSL_accept(ssl);
    int io_errno = errno;
    int result = n == 1 ? 0 : -SSL_get_error(ssl, n);
    mts_sigpipe_guard_end(&guard, io_errno);
    return result;
}

/* Returns bytes read (> 0), 0 on clean TLS EOF (close_notify), or the
 * negated SSL_get_error class (< 0). */
int mts_ssl_read(void *s, unsigned char *buf, int len) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    mts_sigpipe_guard guard;
    if (mts_sigpipe_guard_begin(&guard) != 0) return -SSL_ERROR_SYSCALL;
    ERR_clear_error();
    errno = 0;
    int n = SSL_read(ssl, buf, len);
    int io_errno = errno;
    int result;
    if (n > 0) {
        result = n;
    } else {
        int error = SSL_get_error(ssl, n);
        result = error == SSL_ERROR_ZERO_RETURN ? 0 : -error;
    }
    mts_sigpipe_guard_end(&guard, io_errno);
    return result;
}

/* Returns bytes written (> 0) or the negated SSL_get_error class. */
int mts_ssl_write(void *s, const unsigned char *buf, int len) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    mts_sigpipe_guard guard;
    if (mts_sigpipe_guard_begin(&guard) != 0) return -SSL_ERROR_SYSCALL;
    ERR_clear_error();
    errno = 0;
    int n = SSL_write(ssl, buf, len);
    int io_errno = errno;
    int result = n > 0 ? n : -SSL_get_error(ssl, n);
    mts_sigpipe_guard_end(&guard, io_errno);
    return result;
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

#define MTS_MAX_SESSION_DER (16 * 1024)

/* Copies a resumable session ticket as DER. Returns the length, 0 when no
 * resumable ticket is available yet, or a negative value on failure.
 * TLS 1.3 tickets often arrive after the handshake, so callers should
 * exchange application data first. Early data is never enabled. */
int mts_ssl_export_session(void *s, unsigned char *out, int cap) {
    SSL_SESSION *sess;
    int needed;
    unsigned char *cursor;
    int written;

    if (!s || !out || cap <= 0 || cap > MTS_MAX_SESSION_DER) return -1;
    ERR_clear_error();
    sess = SSL_get1_session(((mts_ssl *)s)->ssl);
    if (!sess) {
        ERR_clear_error();
        return 0;
    }
    if (!SSL_SESSION_is_resumable(sess)) {
        SSL_SESSION_free(sess);
        ERR_clear_error();
        return 0;
    }
    needed = i2d_SSL_SESSION(sess, NULL);
    if (needed <= 0 || needed > MTS_MAX_SESSION_DER || needed > cap) {
        SSL_SESSION_free(sess);
        return -1;
    }
    cursor = out;
    written = i2d_SSL_SESSION(sess, &cursor);
    SSL_SESSION_free(sess);
    if (written != needed) return -1;
    ERR_clear_error();
    return written;
}

/* Installs a previously exported session for the next handshake. A ticket
 * does not send 0-RTT application data. Returns 0 on success. */
int mts_ssl_set_session(void *s, const unsigned char *der, int len) {
    const unsigned char *cursor;
    SSL_SESSION *sess;
    int rc;

    if (!s || !der || len <= 0 || len > MTS_MAX_SESSION_DER) return -1;
    ERR_clear_error();
    cursor = der;
    sess = d2i_SSL_SESSION(NULL, &cursor, (long)len);
    if (!sess) return -1;
    SSL_SESSION_set_max_early_data(sess, 0);
    rc = SSL_set_session(((mts_ssl *)s)->ssl, sess);
    SSL_SESSION_free(sess);
    return rc == 1 ? 0 : -1;
}

int mts_ssl_session_reused(void *s) {
    return SSL_session_reused(((mts_ssl *)s)->ssl) ? 1 : 0;
}

long mts_ssl_verify_result(void *s) {
    return SSL_get_verify_result(((mts_ssl *)s)->ssl);
}

/* Returns the DER length of the peer's leaf certificate, 0 when the peer did
 * not present one, or a negative value on encoding or size failure. The X509
 * reference stays inside this call. */
int mts_ssl_peer_certificate_der_size(void *s) {
    ERR_clear_error();
    X509 *cert = SSL_get1_peer_certificate(((mts_ssl *)s)->ssl);
    if (!cert) {
        ERR_clear_error();
        return 0;
    }
    int length = i2d_X509(cert, NULL);
    X509_free(cert);
    if (length <= 0) return -1;
    if (length > MTS_MAX_PEER_CERT_DER) {
        ERR_clear_error();
        return -2;
    }
    ERR_clear_error();
    return length;
}

/* Copies the peer leaf certificate into caller-owned storage. No OpenSSL
 * allocation or borrowed pointer crosses this boundary. */
int mts_ssl_peer_certificate_der(void *s, unsigned char *out, int cap) {
    if (!out || cap <= 0 || cap > MTS_MAX_PEER_CERT_DER) return -1;

    ERR_clear_error();
    X509 *cert = SSL_get1_peer_certificate(((mts_ssl *)s)->ssl);
    if (!cert) {
        ERR_clear_error();
        return 0;
    }
    int needed = i2d_X509(cert, NULL);
    if (needed <= 0 || needed > MTS_MAX_PEER_CERT_DER || needed > cap) {
        X509_free(cert);
        return -1;
    }
    unsigned char *cursor = out;
    int written = i2d_X509(cert, &cursor);
    X509_free(cert);
    if (written != needed) return -1;
    ERR_clear_error();
    return written;
}

/* Verification success is meaningful only when a certificate exists and the
 * session was configured to verify the peer. SSL_get_verify_result alone can
 * report X509_V_OK when verification was disabled. */
int mts_ssl_peer_certificate_verified(void *s) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    X509 *cert = SSL_get1_peer_certificate(ssl);
    if (!cert) return 0;
    X509_free(cert);
    if ((SSL_get_verify_mode(ssl) & SSL_VERIFY_PEER) == 0) return 0;
    return SSL_get_verify_result(ssl) == X509_V_OK ? 1 : 0;
}

/* Copies the certificate name matched by OpenSSL hostname verification. The
 * borrowed SSL_get0_peername pointer never leaves this function. */
int mts_ssl_peer_name(void *s, char *out, int cap) {
    if (!out || cap <= 0 || cap > MTS_MAX_PEER_NAME) return -1;
    if (mts_ssl_peer_certificate_verified(s) != 1) return 0;

    const char *name = SSL_get0_peername(((mts_ssl *)s)->ssl);
    if (!name) return 0;
    size_t length = 0;
    while (length < (size_t)cap && name[length] != '\0') length++;
    if (length == (size_t)cap) return -1;
    memcpy(out, name, length);
    return (int)length;
}

/* Copies supported subject alternative names into caller-owned storage.
 * Each record is a one-byte kind, a two-byte big-endian length, then the
 * value bytes. DNS, URI, and email entries must contain printable ASCII. IP
 * entries use the canonical text returned by inet_ntop. Other GeneralName
 * choices are omitted. The entry count, each value, and the complete copy are
 * bounded. */
int mts_ssl_peer_subject_alt_names(void *s, unsigned char *out, int cap) {
    if (!s || !out || cap <= 0 || cap > MTS_MAX_PEER_SAN_BYTES) return -1;

    ERR_clear_error();
    X509 *cert = SSL_get1_peer_certificate(((mts_ssl *)s)->ssl);
    if (!cert) {
        ERR_clear_error();
        return 0;
    }

    int extension_status = -1;
    GENERAL_NAMES *names = X509_get_ext_d2i(
        cert, NID_subject_alt_name, &extension_status, NULL);
    X509_free(cert);
    if (!names) {
        ERR_clear_error();
        return extension_status == -1 ? 0 : -4;
    }

    int entry_count = sk_GENERAL_NAME_num(names);
    if (entry_count == 0) {
        GENERAL_NAMES_free(names);
        ERR_clear_error();
        return -4;
    }
    if (entry_count < 0 || entry_count > MTS_MAX_PEER_SAN_COUNT) {
        GENERAL_NAMES_free(names);
        ERR_clear_error();
        return -2;
    }

    int written = 0;
    for (int index = 0; index < entry_count; index++) {
        GENERAL_NAME *name = sk_GENERAL_NAME_value(names, index);
        const unsigned char *value = NULL;
        int value_length = 0;
        int kind = 0;
        char ip_text[INET6_ADDRSTRLEN];

        if (!name) {
            GENERAL_NAMES_free(names);
            ERR_clear_error();
            return -4;
        }
        switch (name->type) {
            case GEN_DNS:
                kind = MTS_SAN_DNS;
                value = ASN1_STRING_get0_data(name->d.dNSName);
                value_length = ASN1_STRING_length(name->d.dNSName);
                break;
            case GEN_URI:
                kind = MTS_SAN_URI;
                value = ASN1_STRING_get0_data(name->d.uniformResourceIdentifier);
                value_length = ASN1_STRING_length(
                    name->d.uniformResourceIdentifier);
                break;
            case GEN_EMAIL:
                kind = MTS_SAN_EMAIL;
                value = ASN1_STRING_get0_data(name->d.rfc822Name);
                value_length = ASN1_STRING_length(name->d.rfc822Name);
                break;
            case GEN_IPADD: {
                const unsigned char *address = ASN1_STRING_get0_data(
                    name->d.iPAddress);
                int address_length = ASN1_STRING_length(name->d.iPAddress);
                int family = address_length == 4 ? AF_INET : AF_INET6;
                if ((address_length != 4 && address_length != 16) ||
                    !address || !inet_ntop(family, address, ip_text,
                                           sizeof(ip_text))) {
                    GENERAL_NAMES_free(names);
                    ERR_clear_error();
                    return -4;
                }
                kind = MTS_SAN_IP;
                value = (const unsigned char *)ip_text;
                value_length = (int)strlen(ip_text);
                break;
            }
            default:
                continue;
        }

        if (!value || value_length <= 0 ||
            value_length > MTS_MAX_PEER_SAN_VALUE) {
            GENERAL_NAMES_free(names);
            ERR_clear_error();
            return -4;
        }
        if (kind != MTS_SAN_IP) {
            for (int offset = 0; offset < value_length; offset++) {
                if (value[offset] < 0x20 || value[offset] > 0x7e) {
                    GENERAL_NAMES_free(names);
                    ERR_clear_error();
                    return -4;
                }
            }
        }
        if (written > cap - 3 - value_length ||
            written > MTS_MAX_PEER_SAN_BYTES - 3 - value_length) {
            GENERAL_NAMES_free(names);
            ERR_clear_error();
            return -3;
        }

        out[written++] = (unsigned char)kind;
        out[written++] = (unsigned char)((value_length >> 8) & 0xff);
        out[written++] = (unsigned char)(value_length & 0xff);
        memcpy(out + written, value, (size_t)value_length);
        written += value_length;
    }

    GENERAL_NAMES_free(names);
    ERR_clear_error();
    return written;
}

int mts_ssl_shutdown(void *s) {
    /* TLSStream.close treats shutdown as best-effort, so do not let an
     * ignored teardown error leak into the next session on this thread. */
    mts_sigpipe_guard guard;
    if (mts_sigpipe_guard_begin(&guard) != 0) return -1;
    ERR_clear_error();
    errno = 0;
    int rc = SSL_shutdown(((mts_ssl *)s)->ssl);
    int io_errno = errno;
    ERR_clear_error();
    mts_sigpipe_guard_end(&guard, io_errno);
    return rc;
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
