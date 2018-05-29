/*
 * Author: Pavol Vican
 * Date: 22.05.2018
 */

#include <openssl/x509.h>
#include <libyang/libyang.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <curl/curl.h>
#include <unistd.h>
#include "zerotouch.h"


#define CHECK_RC_RETURN(RC) if (RC != SR_ERR_OK) { return rc; }
#define SR_STORED_KEYS_DIR "/etc/sysrepo/KEY_STORE/"

struct boostrap_server {
    char *ip;
    uint16_t port;
};

int
dwn_parse_bootstrap_data(struct zt_ctx *ctx, struct bootstrap_data *bootstrap, X509_STORE *store_voucher, int is_xml, int trust_state);

char *
dwn_decode_base64(const char *mem, int size)
{
    BIO *bio, *b64, *bio_out;
    char inbuf[512], *str;
    int inlen, n;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(mem, size);
    bio_out = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);
    while ((inlen = BIO_read(b64, inbuf, 512)) > 0) {
        BIO_write(bio_out, inbuf, inlen);
    }

    BIO_flush(bio_out);
    n = BIO_pending(bio_out);

    str = malloc(n);
    if (str == NULL) {
        SR_LOG_ERR("Unable to allocate memory in %s", __func__);
        return NULL;
    }

    BIO_read(bio_out, str, n);
    str[n - 1] = '\0';

    BIO_free(b64);
    BIO_free(bio);
    BIO_free(bio_out);

    return str;
}

int
dwn_load_voucher_certs(dm_data_info_t *key_store, X509_STORE *voucher)
{
    unsigned int i;
    struct ly_set *set = NULL;
    struct lyd_node *node;
    X509 *cert;

    set = lyd_find_path(key_store->node, "/ietf-keystore:keystore/pinned-certificates['zt-voucher']/pinned-certificate");
    if (!set) {
        SR_LOG_ERR_MSG("Voucher certificates are not available");
        return SR_ERR_DATA_MISSING;
    }

    for(i = 0; i < set->number; ++i) {
        node = set->set.d[i];
        if (strcmp(node->schema->name, "data") != 0) {
            node = node->next;
        }

        cert = vm_base64der_to_cert(((struct lyd_node_leaf_list *)node)->value_str);
        if (!cert) {
            continue;
        }

        X509_STORE_add_cert(voucher, cert);
        X509_free(cert);
    }

    ly_set_free(set);
    return SR_ERR_OK;
}

int
dwn_load_bootstrap_certs(dm_data_info_t *key_store, STACK_OF(X509) *stack_certs)
{
    unsigned int i;
    struct ly_set *set = NULL;
    struct lyd_node *node;
    X509 *cert;

    set = lyd_find_path(key_store->node, "/ietf-keystore:keystore/pinned-certificates['zt-bootstrap']/pinned-certificate");
    if (!set) {
        return SR_ERR_OK;
    }

    for(i = 0; i < set->number; ++i) {
        node = set->set.d[i];
        if (strcmp(node->schema->name, "data") != 0) {
            node = node->next;
        }

        cert = vm_base64der_to_cert(((struct lyd_node_leaf_list *)node)->value_str);
        if (!cert) {
            continue;
        }

        sk_X509_push(stack_certs, cert);
    }

    ly_set_free(set);
    return SR_ERR_OK;
}

int
dwn_load_tls_cert(struct zt_tls_certificate *tls_certs)
{
    CMS_ContentInfo *cms = NULL;
    BIO *input_CMS, *input_key;
    int rc = SR_ERR_OK;

    input_CMS = BIO_new_file(SR_INTERNAL_DATA_SEARCH_DIR"zt-tls.cms.pem", "r");
    if (!input_CMS) {
        SR_LOG_ERR_MSG("TLS certificate are not available");
        return SR_ERR_DATA_MISSING;
    }

    input_key = BIO_new_file(SR_STORED_KEYS_DIR"zt-tls.key.pem", "r");
    if (!input_key) {
        SR_LOG_ERR_MSG("TLS key are not available");
        BIO_free(input_CMS);
        return SR_ERR_DATA_MISSING;
    }

    cms = PEM_read_bio_CMS(input_CMS, NULL, NULL, NULL);
    if (!cms) {
        SR_LOG_ERR_MSG("Invalid TLS certificate");
        rc = SR_ERR_DATA_MISSING;
        goto cleanup;
    }

    tls_certs->client_intermediate_certs = CMS_get1_certs(cms);
    tls_certs->client_cert = sk_X509_shift(tls_certs->client_intermediate_certs);

    tls_certs->client_key = PEM_read_bio_PrivateKey(input_key, NULL, NULL, NULL);
    if (!tls_certs->client_key) {
        SR_LOG_ERR_MSG("Invalid TLS key");
        rc = SR_ERR_DATA_MISSING;
    }

cleanup:
    CMS_ContentInfo_free(cms);
    BIO_free(input_CMS);
    BIO_free(input_key);

    return rc;
}

int
dwn_load_decrypted_key(EVP_PKEY **pkey)
{
    BIO *input;

    input = BIO_new_file(SR_STORED_KEYS_DIR"zt-encryption.key.pem", "r");
    if (!input) {
        SR_LOG_DBG_MSG("Decryption key are not available");
        return SR_ERR_OK;
    }

    *pkey = PEM_read_bio_PrivateKey(input, NULL, NULL, NULL);
    if (!*pkey) {
        SR_LOG_ERR_MSG("Invalid decryption key");
        return SR_ERR_DATA_MISSING;
    }

    return SR_ERR_OK;
}

int
dwn_load_certificates(dm_data_info_t *key_store, X509_STORE **voucher, EVP_PKEY **decrypted_key, struct zt_tls_certificate **tls_certs)
{
    int rc;

    /* allocation memory */
    *voucher = X509_STORE_new();
    CHECK_NULL_NOMEM_RETURN(*voucher);

    *tls_certs = calloc(1, sizeof **tls_certs);
    CHECK_NULL_NOMEM_RETURN(*tls_certs);

    (*tls_certs)->configure_certs = sk_X509_new_null();
    CHECK_NULL_NOMEM_RETURN((*tls_certs)->configure_certs);

    (*tls_certs)->learned_certs = sk_X509_new_null();
    CHECK_NULL_NOMEM_RETURN((*tls_certs)->learned_certs);

    rc = dwn_load_voucher_certs(key_store, *voucher);
    //CHECK_RC_RETURN(rc);

    rc = dwn_load_bootstrap_certs(key_store, (*tls_certs)->configure_certs);
    CHECK_RC_RETURN(rc);

    rc = dwn_load_tls_cert(*tls_certs);
    CHECK_RC_RETURN(rc);

    rc = dwn_load_decrypted_key(decrypted_key);

    return rc;
}

int
dwn_load_bootstrap_servers(struct ly_ctx *ctx, struct boostrap_server **servers)
{
    unsigned int i;
    int rc = SR_ERR_OK;
    struct lyd_node *root;
    struct lyd_node_leaf_list *leaf;
    struct ly_set *set = NULL;

    root = lyd_parse_path(ctx, SR_INTERNAL_DATA_SEARCH_DIR"bootstrap.xml", LYD_XML, LYD_OPT_GET);
    if (!root) {
        return SR_ERR_OK;
    }

    set = lyd_find_path(root, "/zerotouch-device:zerotouch/bootstrap-servers/bootstrap-server");
    if (!set) {
        goto cleanup;
    }

    *servers = calloc(set->number + 1, sizeof **servers);
    CHECK_NULL_NOMEM_GOTO(*servers, rc, cleanup);

    for(i = 0; i < set->number; ++i) {
        leaf = ((struct lyd_node_leaf_list *)set->set.d[i]->child);
        (*servers)[i].ip = strdup(leaf->value_str);
        (*servers)[i].port = ((struct lyd_node_leaf_list *)leaf->next)->value.uint16;
    }

cleanup:
    ly_set_free(set);
    lyd_free(root);
    return rc;
}

void
free_bootstrap_data(struct bootstrap_data *data)
{
    if (!data) {
        return;
    }

    CMS_ContentInfo_free(data->zerotouch);
    CMS_ContentInfo_free(data->certificate);
    CMS_ContentInfo_free(data->voucher);
    free(data);
}

void free_bootstrap_servers(struct boostrap_server *data)
{
    struct boostrap_server *iter = data;

    if (!data) {
        return;
    }

    while(iter->ip) {
        free(iter->ip);
        ++iter;
    }
    free(data);
}

void
free_tls_certs(struct zt_tls_certificate *tls)
{
    if (!tls) {
        return;
    }

    EVP_PKEY_free(tls->client_key);
    X509_free(tls->client_cert);
    sk_X509_pop_free(tls->learned_certs, X509_free);
    sk_X509_pop_free(tls->configure_certs, X509_free);
    sk_X509_pop_free(tls->client_intermediate_certs, X509_free);
    free(tls);
}

void
free_zt_ctx(struct zt_ctx *ctx)
{
    ly_ctx_destroy(ctx->ly_ctx, NULL);
    free_tls_certs(ctx->tls_certs);
    if (ctx->rc_connection) {
        curl_easy_cleanup(ctx->rc_connection);
    }
    free(ctx);
}

struct bootstrap_data *
dwn_download_usb_data()
{
    BIO *zt_info, *zt_owner, *zt_voucher;
    struct bootstrap_data *data = NULL;

    if (0 != access("/mnt/zerotouch/", F_OK)) {
        return NULL;
    }

    zt_info = BIO_new_file("/mnt/zerotouch/zerotouch-information.pem", "r");
    zt_owner = BIO_new_file("/mnt/zerotouch/owner-certificate.pem", "r");
    zt_voucher = BIO_new_file("/mnt/zerotouch/voucher-certificate.pem", "r");

    if (zt_info == NULL) {
        goto cleanup;
    }

    if ((zt_owner != NULL && zt_voucher == NULL) || (zt_owner == NULL && zt_voucher != NULL)) {
        goto cleanup;
    }

    data = calloc(1, sizeof *data);
    data->zerotouch = PEM_read_bio_CMS(zt_info, NULL, NULL, NULL);
    if (zt_owner != NULL) {
        data->voucher = PEM_read_bio_CMS(zt_voucher, NULL, NULL, NULL);
        data->certificate = PEM_read_bio_CMS(zt_owner, NULL, NULL, NULL);
    }

cleanup:
    BIO_free(zt_info);
    BIO_free(zt_owner);
    BIO_free(zt_voucher);

    return data;
}

int
dwn_apply_config_data(struct zt_ctx *ctx, struct lyd_node *root)
{
    dm_data_info_t *info;
    struct lyd_node *node, *iter, *next = NULL;
    const char *name;

    CHECK_NULL_ARG2(ctx, root);

    node = root;
    SR_LOG_DBG_MSG("Apply bootstrap config data");
    do {
        name = root->schema->module->name;
        node = root->next;
        lyd_unlink(root);
        LY_TREE_FOR_SAFE(node, next, iter) {
            if (iter->schema->module->name == name) {
                /* begin node does not lose */
                if (node == iter) {
                    node = iter->next;
                }

                lyd_unlink(iter);
                lyd_insert_sibling(&root, iter);
            }
        }

        dm_get_data_info(ctx->dm_ctx, ctx->session_ctx, name, &info);
        info->node = root;
        info->modified = true;
        SR_LOG_DBG("Module: %s was modified", name);
        root = node;
    } while (node != NULL);

    return SR_ERR_OK;
}

/* return value
 * 0 - apply zero touch
 * 1 - not found data
 * */
int
dwn_parse_redirect(struct zt_ctx *ctx, struct lyd_node *root, X509_STORE *store_voucher, int trust_state)
{
    struct lyd_node *node;
    struct lyd_node_leaf_list *leaf;
    const char *address = NULL, *trust_anchor;
    char ip[33];
    uint16_t port = 443;
    struct hostent *he;
    struct in_addr **addr_list;
    int i, finish_state;
    int is_xml;
    X509 *cert;
    struct bootstrap_data *bootstrap;


    /* node is list of bootstrap servers */
    for(node = root->child; node; node = node->next) {
        trust_anchor = NULL;
        cert = NULL;

        /* read redirect info - one server */
        for(leaf = (struct lyd_node_leaf_list *)node->child; leaf; leaf = (struct lyd_node_leaf_list *)leaf->next) {
            if (!strcmp(leaf->schema->name, "address")) {
                address = leaf->value_str;
            } else if (!strcmp(leaf->schema->name, "port")) {
                port = leaf->value.uint16;
            } else {
                trust_anchor = leaf->value_str;
            }
        }

        /* if trust-state is false, device must discard trust-anchor */
        if (trust_state) {
            trust_anchor = NULL;
        }

        /* if trust-anchor isn't, trust-state must be setting to FALSE */
        if (trust_anchor == NULL) {
            trust_state = FALSE;
        }

        /* learn new cert */
        if (trust_anchor != NULL) {
            cert = vm_base64der_to_cert(trust_anchor);
            /* check if certificate is valid */
            if (cert) {
                sk_X509_push(ctx->tls_certs->learned_certs, cert);
            }
        }

        if (address && !(he = gethostbyname(address))) {
            /* error - not resolve address (continue to next server)*/
            continue;
        }
        addr_list = (struct in_addr **) he->h_addr_list;

        for(i = 0; addr_list[i] != NULL; i++)
        {
            strcpy(ip, inet_ntoa(*addr_list[i]));
            bootstrap = rc_download(ctx, ip, port, &is_xml, &trust_state);
            finish_state = (bootstrap != NULL) ? dwn_parse_bootstrap_data(ctx, bootstrap, store_voucher, is_xml, trust_state)
                                               : FALSE;
            free_bootstrap_data(bootstrap);
            if (finish_state) {
                return 0;
            }
        }

        /* clean learned cert */
        if (cert) {
            cert = sk_X509_pop(ctx->tls_certs->learned_certs);
            X509_free(cert);
        }
    }

    return 1;
}

/* return value
 * 0 - OK
 * 1 - ERROR
 * */
int
dwn_parse_configuration(struct zt_ctx *ctx, struct lyd_node *root)
{
    struct lyd_node *node, *image;
    struct lyd_node_leaf_list *leaf;
    int replace_conf = TRUE, rc = 0;
    char *pre_script = NULL, *post_script = NULL, *data = NULL;


    for (node = root->child; node; node = node->next) {
        if (!strcmp(node->schema->name, "boot-image")) {
            image = node->child;
        } else if (!strcmp(node->schema->name, "configuration-handling")) {
            leaf = (struct lyd_node_leaf_list *)node;
            replace_conf = (!strcmp(leaf->value_str, "replace")) ? TRUE : FALSE;
        } else if (!strcmp(node->schema->name, "pre-configuration-script")) {
            leaf = (struct lyd_node_leaf_list *)node;
            pre_script = dwn_decode_base64(leaf->value_str, strlen(leaf->value_str));
        } else if (!strcmp(node->schema->name, "post-configuration-script")) {
            leaf = (struct lyd_node_leaf_list *)node;
            post_script = dwn_decode_base64(leaf->value_str, strlen(leaf->value_str));
        } else {
            /* configuration data */
            leaf = (struct lyd_node_leaf_list *)node;
            data = dwn_decode_base64(leaf->value_str, strlen(leaf->value_str));
        }
    }

    /* check boot-image */

    /* run pre-configuration-script */

    /* run post-configuration-script */

cleanup:
    free(pre_script);
    free(post_script);
    free(data);
    return rc;
}

/* return value
 * 0 - apply zero touch
 * 1 - not found data
 * */
int
dwn_parse_bootstrap_data(struct zt_ctx *ctx, struct bootstrap_data *bootstrap, X509_STORE *store_voucher, int is_xml, int trust_state)
{
    const char *data;
    struct lyd_node *root;
    int sign, rc = 1;

    data = vm_verify_zt_data(ctx->ly_ctx, bootstrap, store_voucher, ctx->tls_certs, is_xml, &sign);
    root = lyd_parse_mem(ctx->ly_ctx, data, (is_xml) ? LYD_XML : LYD_JSON, LYD_OPT_DATA_TEMPLATE , "zerotouch-information");

    if (!root) {
        return 1;
    }

    if (sign) {
        trust_state = TRUE;
    }

    if (!strcmp(root->schema->name, "redirect-information")) {
        if (ctx->rc_connection) {
            curl_easy_cleanup(ctx->rc_connection);
        }

        rc = dwn_parse_redirect(ctx, root, store_voucher, trust_state);
    } else {
        if (!trust_state) {
            goto cleanup;
        }

        /*
         * struct lyd_node *node;
            node = lyd_parse_path(tmp_ctx->ctx, "/home/xvican01/test.xml", LYD_XML, LYD_OPT_CONFIG);
         * lyd_parse_mem(ctx, "", LYD_XML, LYD_OPT_CONFIG);
         * apply_config_data(ctx, dm_session, node);
         * */
        }

cleanup:
    lyd_free(root);
    return rc;
}

int
dwn_run_zerotouch(dm_ctx_t *dm_ctx, dm_session_t *dm_session, struct ly_ctx *ly_ctx, dm_data_info_t *key_store)
{
    X509_STORE *store_voucher = NULL;
    struct bootstrap_data *bootstrap = NULL;
    struct boostrap_server *servers = NULL;
    int is_xml, trusted_state = FALSE, finish_state = FALSE;
    EVP_PKEY *decrypted_key = NULL;
    int rc, i;
    struct zt_ctx *zt_ctx;

    /* init part */
    OpenSSL_add_all_algorithms();
    curl_global_init(CURL_GLOBAL_DEFAULT);

    zt_ctx = calloc(1, sizeof *zt_ctx);
    CHECK_NULL_NOMEM_RETURN(zt_ctx);
    zt_ctx->ly_ctx = ly_ctx;
    zt_ctx->dm_ctx = dm_ctx;
    zt_ctx->session_ctx = dm_session;

    rc = dwn_load_certificates(key_store, &store_voucher, &decrypted_key, &(zt_ctx->tls_certs));
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed loading certificates.");

    rc = dwn_load_bootstrap_servers(ly_ctx, &servers);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed loading well-known bootstrap servers.");

    /* begin algorithm */
    bootstrap = dwn_download_usb_data();
    if (bootstrap != NULL) {
        finish_state = dwn_parse_bootstrap_data(zt_ctx, bootstrap, store_voucher, is_xml, trusted_state);
    }

    /* try iterate list of well-know bootstrap servers */
    i = 0;
    while (finish_state == FALSE && servers[i].ip != NULL) {
        bootstrap = rc_download(zt_ctx, servers[i].ip, servers[i].port, &is_xml, &trusted_state);
        if (bootstrap != NULL) {
            finish_state = dwn_parse_bootstrap_data(zt_ctx, bootstrap, store_voucher, is_xml, trusted_state);
        }

        ++i;
    }

    rc = SR_ERR_OK;

cleanup:
    curl_global_cleanup();
    free_bootstrap_data(bootstrap);
    X509_STORE_free(store_voucher);
    EVP_PKEY_free(decrypted_key);
    free_bootstrap_servers(servers);
    free_zt_ctx(zt_ctx);
    return rc;
}