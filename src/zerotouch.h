/*
 * Author: Pavol Vican
 * Date: 22.05.2018
 */

#include <openssl/cms.h>
#include <libyang/libyang.h>
#include <curl/curl.h>
#include "data_manager.h"

#define TRUE 1
#define FALSE 0

struct bootstrap_data {
    CMS_ContentInfo *zerotouch;
    CMS_ContentInfo *certificate;
    CMS_ContentInfo *voucher;
};

struct zt_tls_certificate {
    X509 *client_cert;
    EVP_PKEY *client_key;
    STACK_OF(X509) *configure_certs;
    STACK_OF(X509) *learned_certs;
    STACK_OF(X509) *client_intermediate_certs;
};

struct zt_ctx {
    dm_ctx_t *dm_ctx;
    dm_session_t *session_ctx;
    struct ly_ctx *ly_ctx;
    struct zt_tls_certificate *tls_certs;
    CURL *rc_connection;
};

struct bootstrap_data *rc_download(struct zt_ctx* ctx, const char *ip, uint16_t port, int *is_xml, int *trust_state);

const char *vm_verify_zt_data(struct ly_ctx *ctx, struct bootstrap_data *boostrap, X509_STORE *voucher,
                              struct zt_tls_certificate *tls, int is_xml, int *sign);

CMS_ContentInfo *vm_base64_to_cms(const char *in);
X509 *vm_base64der_to_cert(const char *in);
int dwn_run_zerotouch(dm_ctx_t *dm_ctx, dm_session_t *dm_session, struct ly_ctx *ly_ctx, dm_data_info_t *key_store);