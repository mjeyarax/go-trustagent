#include "tpm20linux.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>

// KWT:  Can probably remove this file unless we need to turn the EK modulus
// into PEM.

// from https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/lib/conversion.c
int Tpm2bPublic2PemBuffer(TPMT_PUBLIC* public, char** out, int outLength)
{
    RSA *ssl_rsa_key = NULL;
    BIO* bio = NULL;
    BIGNUM *e = NULL, *n = NULL;
    
    // need this before the first SSL call for getting human readable error
    // strings in print_ssl_error()
    ERR_load_crypto_strings();

    if (public->type != TPM2_ALG_RSA) {
        ERROR("Unsupported key type for requested output format. Only RSA is supported.");
        return -1;
    }

    UINT32 exponent = (public->parameters).rsaDetail.exponent;
    if (exponent == 0) {
        exponent = 0x10001;
    }

    // OpenSSL expects this in network byte order
    //exponent = tpm2_util_hton_32(exponent);
    
    ssl_rsa_key = RSA_new();
    if (!ssl_rsa_key) 
    {
        ERROR("Failed to allocate OpenSSL RSA structure");
        return -1;
    }

    e = BN_bin2bn((void*)&exponent, sizeof(exponent), NULL);
    n = BN_bin2bn(public->unique.rsa.buffer, public->unique.rsa.size, NULL);

#if OPENSSL_VERSION_NUMBER < 0x1010000fL /* OpenSSL 1.1.0 */
    ssl_rsa_key->e = e;
    ssl_rsa_key->n = n;
#else
    if (!RSA_set0_key(ssl_rsa_key, n, e, NULL)) {
        ERROR("Failed to set RSA modulus and exponent components");
        return -1;
    }
#endif

    /* modulus and exponent components are now owned by the RSA struct */
    n = e = NULL;

    bio = BIO_new(BIO_s_mem());
    if(!bio)
    {
        ERROR("Faile to create 'bio'");
        return -1;
    }

    int ssl_res = PEM_write_bio_RSA_PUBKEY(bio, ssl_rsa_key);
    if (ssl_res <= 0) {
        ERROR("OpenSSL public key conversion failed: %x", ssl_res);
        return ssl_res;
    }

    if (n) {
        BN_free(n);
    }
    if (e) {
        BN_free(e);
    }

    if (ssl_rsa_key) {
        RSA_free(ssl_rsa_key);
    }

    ERR_free_strings();
}