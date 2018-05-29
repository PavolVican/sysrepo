/*
 * Author: Pavol Vican
 * Date: 22.05.2018
 */

#define _GNU_SOURCE

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <string.h>
#include <assert.h>
#include <sysrepo.h>
#include <common/sr_common.h>
#include <ctype.h>
#include "zerotouch.h"

time_t
vm_datetime2time(const char *datetime)
{
    struct tm time;
    char *dt;
    int i;
    long int shift, shift_m;
    time_t retval;

    if (datetime == NULL) {
        return -1;
    }

    dt = strdup(datetime);

    if (strlen(dt) < 20 || dt[4] != '-' || dt[7] != '-' || dt[13] != ':' || dt[16] != ':') {
        SR_LOG_DBG_MSG("Wrong date time format not compliant to RFC 3339.");
        free(dt);
        return SR_ERR_INVAL_ARG;
    }

    memset(&time, 0, sizeof(struct tm));
    time.tm_year = atoi(&dt[0]) - 1900;
    time.tm_mon = atoi(&dt[5]) - 1;
    time.tm_mday = atoi(&dt[8]);
    time.tm_hour = atoi(&dt[11]);
    time.tm_min = atoi(&dt[14]);
    time.tm_sec = atoi(&dt[17]);

    retval = timegm(&time);

    /* apply offset */
    i = 19;
    if (dt[i] == '.') { /* we have fractions to skip */
        for (i++; isdigit(dt[i]); i++)
            ;
    }
    if (dt[i] == 'Z' || dt[i] == 'z') {
        /* zero shift */
        shift = 0;
    } else if (dt[i + 3] != ':') {
        /* wrong format */
        SR_LOG_DBG_MSG("Wrong date time format not compliant to RFC 3339.");
        free(dt);
        return SR_ERR_INVAL_ARG;
    } else {
        shift = strtol(&dt[i], NULL, 10);
        shift = shift * 60 * 60; /* convert from hours to seconds */
        shift_m = strtol(&dt[i + 4], NULL, 10) * 60; /* includes conversion from minutes to seconds */
        /* correct sign */
        if (shift < 0) {
            shift_m *= -1;
        }
        /* connect hours and minutes of the shift */
        shift = shift + shift_m;
    }
    /* we have to shift to the opposite way to correct the time */
    retval -= shift;

    free(dt);
    return retval;
}

CMS_ContentInfo *
vm_base64_to_cms(const char *in)
{
    char *buf;
    BIO *bio;
    CMS_ContentInfo *out;

    if (in == NULL) {
        return NULL;
    }

    if (asprintf(&buf, "%s%s%s", "-----BEGIN CMS-----\n", in, "\n-----END CMS-----") == -1) {
        return NULL;
    }

    bio = BIO_new_mem_buf(buf, strlen(buf));
    if (!bio) {
        free(buf);
        return NULL;
    }

    out = PEM_read_bio_CMS(bio, NULL, NULL, NULL);
    free(buf);
    BIO_free(bio);

    return out;
}

X509 *
vm_base64der_to_cert(const char *in)
{
    X509 *out;
    char *buf;
    BIO *bio;

    if (in == NULL) {
        return NULL;
    }

    if (asprintf(&buf, "%s%s%s", "-----BEGIN CERTIFICATE-----\n", in, "\n-----END CERTIFICATE-----") == -1) {
        return NULL;
    }
    bio = BIO_new_mem_buf(buf, strlen(buf));
    if (!bio) {
        free(buf);
        return NULL;
    }

    out = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!out) {
        free(buf);
        BIO_free(bio);
        return NULL;
    }

    free(buf);
    BIO_free(bio);
    return out;
}

int
vm_read_owner_certificate(CMS_ContentInfo *cms, X509 **owner_cert, STACK_OF(X509) **stack_intermediate_certs)
{
    char buf[64];
    uint32_t key_usage;

    assert(cms);

    OBJ_obj2txt(buf, 63, CMS_get0_type(cms), 1);
    if (strcmp(buf, "1.2.840.113549.1.7.2")) {
        SR_LOG_DBG_MSG("Invalid owner certificate - cms structure");
        return EXIT_FAILURE;
    }

    *stack_intermediate_certs = CMS_get1_certs(cms);
    *owner_cert = sk_X509_shift(*stack_intermediate_certs);

    key_usage = X509_get_key_usage(*owner_cert);
    if (key_usage != UINT32_MAX && !(key_usage & KU_DIGITAL_SIGNATURE)) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int
vm_compare_certificate_pubkey(X509 *sign, X509 *ver)
{
    EVP_PKEY *sign_pkey, *ver_pkey;

    sign_pkey = X509_get0_pubkey(sign);
    ver_pkey = X509_get0_pubkey(ver);

    return EVP_PKEY_cmp(sign_pkey, ver_pkey) == 1 ? EXIT_SUCCESS : EXIT_FAILURE;
}

int
vm_verify_cms(CMS_ContentInfo *cms, X509 *sign_cert, X509_STORE *store)
{
    STACK_OF(X509) *signers;

    if (!CMS_verify(cms, NULL, store, NULL, NULL, 0)) {
        SR_LOG_DBG_MSG("Verification CMS structure failed");
        return EXIT_FAILURE;
    }

    if (sign_cert) {
        signers = CMS_get0_signers(cms);
        X509 *signers_cert = sk_X509_value(signers, 0);
        if (vm_compare_certificate_pubkey(sign_cert, signers_cert)) {
            SR_LOG_DBG_MSG("Failed to compare public key of sign certificate and owner certificate");
            sk_X509_free(signers);
            return EXIT_FAILURE;
        }
        sk_X509_free(signers);
    }

    return EXIT_SUCCESS;
}

time_t
vm_current_time()
{
    time_t current = time(NULL);
    struct tm *gm = gmtime(&current);

    return timegm(gm);
}

const char *
vm_verify_voucher(CMS_ContentInfo *voucher, X509_STORE *st_voucher, int *is_xml)
{
    ASN1_OCTET_STRING **content;
    char content_type[64];

    OBJ_obj2txt(content_type, 63, CMS_get0_type(voucher), 1);
    if (strcmp(content_type, "1.2.840.113549.1.7.2")) {
        SR_LOG_DBG_MSG("Voucher is not signed");
        return NULL;
    }

    if (vm_verify_cms(voucher, NULL, st_voucher)) {
        return NULL;
    }

    OBJ_obj2txt(content_type, 63, CMS_get0_eContentType(voucher), 1);
    if (!strcmp(content_type, "1.2.840.113549.1.9.16.1")) {
        *is_xml = FALSE;
    } else if (strcmp(content_type, "1.2.840.113549.1.7.1")) {
        SR_LOG_DBG_MSG("Voucher has invalid eContent type");
        return NULL;
    }

    content = CMS_get0_content(voucher);

    if (!content || !*content) {
        SR_LOG_DBG_MSG("Invalid voucher - not data!");
        return NULL;
    }

    return (const char *)ASN1_STRING_get0_data(*content);
}

int
vm_is_expired_cert(const X509 *cert)
{
    const ASN1_TIME *time = X509_get0_notAfter(cert);
    return X509_cmp_current_time(time) == 1 ? FALSE : TRUE;
}

int
vm_is_same_serialnumber(const X509 *cert, const char *serial_number)
{
    X509_NAME *name;
    ASN1_OBJECT *serial;
    char buf[256];

    serial = OBJ_txt2obj("2.5.4.5", 1);
    name = X509_get_subject_name(cert);
    X509_NAME_get_text_by_OBJ(name, serial, buf, 256);

    return (strcmp(serial_number, buf) == 0) ? TRUE : FALSE;
}

X509 *
vm_read_voucher(struct ly_ctx *ctx, CMS_ContentInfo *voucher, X509_STORE *st_voucher, struct zt_tls_certificate *tls,
                int is_xml)
{
    const char *data, *serial_number;
    struct lyd_node *node, *iter;
    time_t current_time, create_time;
    X509 *pinned_cert = NULL;
    int check_expiration = FALSE, count, i;

    data = vm_verify_voucher(voucher, st_voucher, &is_xml);
    node = lyd_parse_mem(ctx, data, (is_xml) ? LYD_XML : LYD_JSON, LYD_OPT_DATA_TEMPLATE , "voucher-artifact");
    if (!node) {
        return NULL;
    }

    for(iter = node->child; iter; iter = iter->next) {
        if (!strcmp(iter->schema->name, "created-on")) {
            current_time = vm_current_time();
            create_time = vm_datetime2time(((struct lyd_node_leaf_list *)iter)->value_str);
            if (difftime(current_time, create_time) < 0) {
                SR_LOG_DBG_MSG("Voucher must be create in the past");
                lyd_free(node);
                return NULL;
            }
        }

        if (!strcmp(iter->schema->name, "pinned-domain-cert")) {
            /* found pinned-cert node */
            pinned_cert = vm_base64der_to_cert(((struct lyd_node_leaf_list *)iter)->value_str);
        }

        if (!strcmp(iter->schema->name, "serial-number")) {
            /* found serial number */
            serial_number = ((struct lyd_node_leaf_list *)iter)->value_str;
            if (vm_is_same_serialnumber(tls->client_cert,  serial_number) == FALSE) {
                goto error;
            }
        }

        if (!strcmp(iter->schema->name, "expires-on")) {
            /* need check expiretion data every pinned-domain-certs */
            check_expiration = TRUE;
        }
    }


    lyd_free(node);
    if (check_expiration) {
        if (vm_is_expired_cert(pinned_cert)) {
            goto error;
        }

        count = sk_X509_num(tls->learned_certs);
        for(i = 0; i < count; ++i) {
            if (vm_is_expired_cert(pinned_cert)) {
                goto error;
            }
        }

        count = sk_X509_num(tls->configure_certs);
        for(i = 0; i < count; ++i) {
            if (vm_is_expired_cert(pinned_cert)) {
                goto error;
            }
        }
    }

    return pinned_cert;

error:
    X509_free(pinned_cert);
    return NULL;
}


const char *
vm_verify_zt_data(struct ly_ctx *ctx, struct bootstrap_data *boostrap, X509_STORE *voucher,
                  struct zt_tls_certificate *tls, int is_xml, int *sign)
{
    const char *data = NULL;
    X509 *pinned_cert = NULL;
    X509_STORE *store_pinned_cert = NULL;
    STACK_OF(X509) *stack_chain = NULL;
    X509 *owner = NULL;
    ASN1_OCTET_STRING **content;
    char content_type[64];

    OBJ_obj2txt(content_type, 63, CMS_get0_type(boostrap->zerotouch), 1);
    if (!strcmp(content_type, "1.2.840.113549.1.7.2")) {
        if (!boostrap->certificate || !boostrap->voucher) {
            SR_LOG_DBG_MSG("Missing certificate or voucher");
            return NULL;
        }

        store_pinned_cert = X509_STORE_new();
        if (!store_pinned_cert) {
            SR_LOG_ERR("Unable to allocate memory in %s", __func__);
            return NULL;
        }

        /* set partial chain - intermediate CA certificate can trusted */
        X509_VERIFY_PARAM *vpm = X509_STORE_get0_param(store_pinned_cert);
        X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_PARTIAL_CHAIN);

        pinned_cert = vm_read_voucher(ctx, boostrap->voucher, voucher, tls, is_xml);
        if (!pinned_cert) {
            goto cleanup;
        }

        X509_STORE_add_cert(store_pinned_cert, pinned_cert);

        /* add owner cert to cms structure of zero touch information */
        vm_read_owner_certificate(boostrap->certificate, &owner, &stack_chain);
        while (sk_X509_num(stack_chain)) {
            X509 *cert = sk_X509_pop(stack_chain);
            CMS_add0_cert(boostrap->zerotouch, cert);
        }
        sk_X509_free(stack_chain);
        *sign = TRUE;

        if (vm_verify_cms(boostrap->zerotouch, owner, store_pinned_cert)) {
            goto cleanup;
        }

        OBJ_obj2txt(content_type, 63, CMS_get0_eContentType(boostrap->zerotouch), 1);
    } else {
        *sign = 0;
    }

    if (strcmp(content_type, "1.2.840.113549.1.7.1")) {
        SR_LOG_DBG_MSG("Content type of zero touch artifacts is invalid");
        goto cleanup;
    }

    content = CMS_get0_content(boostrap->zerotouch);

    if (!content || !*content) {
        SR_LOG_DBG_MSG("Invalid zero touch artifact - not data");
        goto cleanup;
    }
    data = (const char *)ASN1_STRING_get0_data(*content);

cleanup:

    X509_free(pinned_cert);
    X509_free(owner);
    X509_STORE_free(store_pinned_cert);

    return data;
}
