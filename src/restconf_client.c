/*
 * Author: Pavol Vican
 * Date: 22.05.2018
 */

#define _GNU_SOURCE

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <common/sr_common.h>

#include "zerotouch.h"

struct http_header {
    int code;
    char *content_type;
};

struct http_body {
    int valid;
    char *content;
};

size_t
header_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    char *s;

    /* convert header fields to lowercase */
    for (s = ptr; *s; ++s) {
        *s = (char)tolower(*s);
    }

    struct http_header *info = userdata;

    /* extract necessary information */
    if (!strncmp(ptr, "http/", 5)) {
        /* skip version http and read return code */
        for (ptr += 5; *ptr && !isspace(*ptr); ++ptr);
        info->code = atoi(ptr);
    } else if (!strncmp(ptr, "content-type:", 13)) {
        /* read content type */
        for (ptr += 13; *ptr && isspace(*ptr); ++ptr);
        for (s = ptr; *s && !isspace(*s); ++s);

        /* alloc and copy data */
        info->content_type = malloc(s - ptr + 1);
        memcpy(info->content_type, ptr, s - ptr);
        info->content_type[s - ptr] = '\0';
    }

    return size * nmemb;
}

size_t
write_callback(char *reply, size_t size, size_t nmemb, void *userdata)
{
    size_t size_content, size_reply;
    struct http_body *body = userdata;
    char *content;


    if (body->valid) {
        if (body->content) {
            size_content = strlen(body->content);
            size_reply = strlen(reply);
            content = realloc(body->content, size_content + size_reply + 1);
            if (content) {
                body->content = content;
                memcpy(content + size_content, reply, size_reply);
            } else {
                body->valid = 0;
            }
        } else {
            body->content = strdup(reply);
            if (!body->content) {
                body->valid = 0;
            }
        }
    }

    return size * nmemb;
}

CURLcode
sslctx_function(CURL *curl, void *sslctx, void *param)
{
    int i, count;
    X509_STORE *store = NULL;
    struct zt_tls_certificate *tls = param;
    SSL_CTX *ctx = sslctx;

    /* unsused variable - disable compiler warning*/
    (void)curl;

    SSL_CTX_use_certificate(ctx, tls->client_cert);
    SSL_CTX_use_PrivateKey(ctx, tls->client_key);

    if(!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "SSL_CTX_check_private_key\n");
        return CURLE_ABORTED_BY_CALLBACK;
    }

    /* get a pointer to the X509 certificate store (which may be empty!) */
    store = SSL_CTX_get_cert_store(ctx);
    if(!store) {
        return CURLE_ABORTED_BY_CALLBACK;
    }

    /* add configured certificate to this store */
    count = sk_X509_num(tls->configure_certs);
    for(i = 0; i < count; ++i) {
       X509_STORE_add_cert(store, sk_X509_value(tls->configure_certs, i));
    }

    /* add configured certificate to this store */
    count = sk_X509_num(tls->learned_certs);
    for(i = 0; i < count; ++i) {
        X509_STORE_add_cert(store, sk_X509_value(tls->configure_certs, i));
    }

    return CURLE_OK;

}

void
set_header(CURL *curl, char *data)
{
    struct curl_slist *headers=NULL;
    headers = curl_slist_append(headers, "Content-Type: application/yang.data+json");

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(data));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
}

void
set_basic_connection(CURL *curl, struct zt_tls_certificate *tls, void *header_callback_data,
                     void *body_callback_data)
{
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, header_callback_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, body_callback_data);

    /* disable default path to ca certificate */
    curl_easy_setopt(curl, CURLOPT_CAPATH, NULL);
    curl_easy_setopt(curl, CURLOPT_CAINFO, NULL);

    /* set client certificate and ca certificate */
    curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, tls);
    curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctx_function);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
}

struct bootstrap_data *
parse_output_data(struct ly_ctx* ctx, const char *data, int is_xml)
{
    struct lyd_node *rpc, *rpc_reply;
    struct lyd_node_leaf_list *iter;
    const struct lys_module* module;
    struct bootstrap_data *bootstrap = NULL;

    module = ly_ctx_get_module(ctx, "ietf-zerotouch-bootstrap-server", "2018-04-16", 1);
    rpc = lyd_new(NULL, module, "get-bootstrapping-data");
    rpc_reply = lyd_parse_mem(ctx, data, (is_xml) ? LYD_XML : LYD_JSON, LYD_OPT_RPCREPLY, rpc, NULL);

    if (!rpc_reply) {
        goto clean;
    }

    bootstrap = calloc(1, sizeof(*bootstrap));
    if (!bootstrap) {
        SR_LOG_ERR("Unable to allocate memory in %s", __func__);
        goto clean;
    }

    iter = (struct lyd_node_leaf_list *)rpc_reply->child;
    bootstrap->zerotouch = vm_base64_to_cms(iter->value_str);
    if (iter->next) {
        /* owner certificate */
        iter = (struct lyd_node_leaf_list *)iter->next;
        bootstrap->certificate = vm_base64_to_cms(iter->value_str);
        /* voucher */
        iter = (struct lyd_node_leaf_list *)iter->next;
        bootstrap->voucher = vm_base64_to_cms(iter->value_str);
    }

clean:
    lyd_free(rpc);
    lyd_free(rpc_reply);
    return bootstrap;
}


struct bootstrap_data *
rc_download(struct zt_ctx* ctx, const char *ip, uint16_t port, int *is_xml, int *trust_state)
{
    CURL *curl;
    CURLcode res;
    struct bootstrap_data *retval = NULL;
    struct http_header header;
    struct http_body body;
    char *url;
    int trust = TRUE;
    char *untrusted_input = "{\n"
            "    \"ietf-zerotouch-bootstrap-server:input\":{\n"
            "        \"untrusted-connection\": [null]\n"
            "    }\n"
            "}";

    /* clean structure */
    header.code = 0;
    header.content_type = NULL;
    body.valid = 1;
    body.content = NULL;

    curl = curl_easy_init();
    if (curl == NULL) {
        SR_LOG_ERR_MSG("Failed initialize RESTCONF client");
        return NULL;
    }

    asprintf(&url, "https://%s:%d/restconf/operations/ietf-zerotouch-bootstrap-server:get-bootstrapping-data", ip, port);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    set_basic_connection(curl, ctx->tls_certs, &header, &body);
    set_header(curl, "");

    /* disconnect if we can't validate server's cert */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);

    if (res == CURLE_SSL_CACERT) {
        /* unable to authenticate the bootstrap server's TLS certificate */
        trust = FALSE;
        set_header(curl, untrusted_input);

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        res = curl_easy_perform(curl);

    }

    /* Check for errors */
    if(res != CURLE_OK) {
        SR_LOG_ERR("%s", curl_easy_strerror(res));
        goto cleanup;
    }

    //printf("Code %d; Content-type: %s\n", header.code, header.content_type);
    //printf("Body: %s\n", body.content);

    if (!strcmp(header.content_type, "application/yang.api+json")) {
        *is_xml = FALSE;
    } else if (!strcmp(header.content_type, "application/yang.api+xml")) {
        *is_xml = TRUE;
    } else {
        SR_LOG_ERR("Unknown http content type: \"%s\"", header.content_type);
        goto cleanup;
    }

    retval = parse_output_data(ctx->ly_ctx, body.content, *is_xml);
    if (retval != NULL) {
        *trust_state = trust;
    }

    /* check if connection is trust and keep open connection */
    if (retval != NULL && trust) {
        ctx->rc_connection = curl;
    } else {
        curl_easy_cleanup(curl);
        ctx->rc_connection = NULL;
    }

cleanup:
    free(url);
    free(body.content);
    free(header.content_type);
    return retval;
}
