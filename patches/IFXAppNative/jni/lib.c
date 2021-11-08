/*
 * ...
 */

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <tpm2-tss-engine.h>
#include <tss2/tss2_tctildr.h>

#include "lib.h"

#define RSA_KEY_PATH "/storage/emulated/0/Download/rsa-key"
#define EC_KEY_PATH "/storage/emulated/0/Download/ec-key"

void init_openssl()
{ 
    OpenSSL_add_all_algorithms();    
    SSL_load_error_strings();  
    SSL_library_init();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

int
rsa_genkey()
{
    RSA *rsa = NULL;
    int ret = -1;

    ALOGI("Generating RSA key using TPM");

    BIGNUM *e = BN_new();
    if (!e) {
        ALOGE("out of memory");
        goto err1;
    }
    BN_set_word(e, /* exponent */ 65537);

    rsa = RSA_new();
    if (!rsa) {
        ALOGE("out of memory");
        goto err2;
    }
    if (!tpm2tss_rsa_genkey(rsa, /* key size */ 2048, e, /* password */ NULL, /* parent keyhandle or TPM2_RH_OWNER or 0 */ 0)) { 
        ALOGE("Error: Generating key failed");
        goto err3;
    }

    ALOGI("RSA Key generated");

    TPM2_DATA *tpm2Data = calloc(1, sizeof(*tpm2Data));
    if (tpm2Data == NULL) {
        ALOGE("out of memory");
        goto err3;
    }

    memcpy(tpm2Data, RSA_get_app_data(rsa), sizeof(*tpm2Data));

    if (!tpm2tss_tpm2data_write(tpm2Data, RSA_KEY_PATH)) {
        ALOGE("Error writing file");
        goto err4;
    }

    ALOGI("RSA Key written to %s", RSA_KEY_PATH);

    ret = 0;

err4:
    free(tpm2Data);
err3:
    RSA_free(rsa);
err2:
    BN_free(e);
err1:
    return ret;
}

int
ec_genkey()
{
    EC_KEY *eckey = NULL;
    int ret = -1;

    ALOGI("Generating EC key using TPM");

    eckey = EC_KEY_new();
    if (!eckey) {
        ALOGE("out of memory");
        goto err1;
    }
    
    //TPM2_ECC_NIST_P256, TPM2_ECC_NIST_P384
    if (!tpm2tss_ecc_genkey(eckey, TPM2_ECC_NIST_P256, /* password */ NULL, /* parent keyhandle or TPM2_RH_OWNER or 0 */ 0)) { 
        ALOGE("Error: Generating key failed");
        goto err2;
    }

    ALOGI("EC Key generated");

    TPM2_DATA *tpm2Data = calloc(1, sizeof(*tpm2Data));
    if (tpm2Data == NULL) {
        ALOGE("out of memory");
        goto err2;
    }

    memcpy(tpm2Data, tpm2tss_ecc_getappdata(eckey), sizeof(*tpm2Data));

    if (!tpm2tss_tpm2data_write(tpm2Data, EC_KEY_PATH)) {
        ALOGE("Error writing file");
        goto err3;
    }

    ALOGI("EC Key written to %s", EC_KEY_PATH);

    ret = 0;

err3:
    free(tpm2Data);
err2:
    EC_KEY_free(eckey);
err1:
    return ret;
}

int
ec_evp_pkey_sign_verify(EVP_PKEY *pKey)
{
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char sha256[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    unsigned char *sig = NULL;
    size_t sha256Len = 32, sigLen = 0;
    int ret = -1;

    ctx = EVP_PKEY_CTX_new(pKey, NULL);
    if (!ctx) {
        ALOGE("EC EVP_PKEY_CTX_new error");
        goto err1;
    }

    /* Signing */

    ALOGI("EC signing");
    
    if (EVP_PKEY_sign_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_sign(ctx, NULL, &sigLen, sha256, sha256Len) <= 0) {
        ALOGE("EC sign init error");
        goto err2;
    }
    
    sig = OPENSSL_malloc(sigLen);
    
    if (!sig) {
        ALOGE("EC malloc error");
        goto err2;
    }

    ALOGI("EC generating signature");

    if (EVP_PKEY_sign(ctx, sig, &sigLen, sha256, sha256Len) <= 0) {
        ALOGE("EC signing error");
        goto err3;
    }
    
    /* Verification */

    ALOGI("EC verify signature");

    if (EVP_PKEY_verify_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        ALOGE("EC verification init error");
        goto err2;
    }

    /* ret == 1 indicates success, 0 verify failure and < 0 for some
     * other error.
     */
    if (EVP_PKEY_verify(ctx, sig, sigLen, sha256, sha256Len) <= 0) {
        ALOGE("EC signature verification error");
        goto err3;
    }

    ALOGI("EC signature verification ok");

    // corrupt the hash
    sha256[3] = 1;
    if (EVP_PKEY_verify(ctx, sig, sigLen, sha256, sha256Len) == 0) {
        ALOGI("EC signature verification expected to fail, ok");
    } else {
        ALOGE("EC signature verification error");
        goto err3;
    }
    
    ret = 0;

err3:
    OPENSSL_free(sig);
err2:
    EVP_PKEY_CTX_free(ctx);
err1:
    return ret;
}

int
rsa_evp_pkey_sign_verify(EVP_PKEY *pKey)
{
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char sha256[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    unsigned char *sig = NULL;
    size_t sha256Len = 32, sigLen = 0;
    int ret = -1;

    ctx = EVP_PKEY_CTX_new(pKey, NULL);
    if (!ctx) {
        ALOGE("RSA EVP_PKEY_CTX_new error");
        goto err1;
    }

    /* Signing */

    ALOGI("RSA signing");
    
    if (EVP_PKEY_sign_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_sign(ctx, NULL, &sigLen, sha256, sha256Len) <= 0) {
        ALOGE("RSA sign init error");
        goto err2;
    }
    
    sig = OPENSSL_malloc(sigLen);
    
    if (!sig) {
        ALOGE("RSA malloc error");
        goto err2;
    }

    ALOGI("RSA generating signature");

    if (EVP_PKEY_sign(ctx, sig, &sigLen, sha256, sha256Len) <= 0) {
        ALOGE("RSA signing error");
        goto err3;
    }
    
    /* Verification */

    ALOGI("RSA verify signature");

    if (EVP_PKEY_verify_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        ALOGE("RSA verification init error");
        goto err2;
    }

    /* ret == 1 indicates success, 0 verify failure and < 0 for some
     * other error.
     */
    if (EVP_PKEY_verify(ctx, sig, sigLen, sha256, sha256Len) <= 0) {
        ALOGE("RSA signature verification error");
        goto err3;
    }

    ALOGI("RSA signature verification ok");

    // corrupt the hash
    sha256[3] = 1;
    if (EVP_PKEY_verify(ctx, sig, sigLen, sha256, sha256Len) == 0) {
        ALOGI("RSA signature verification expected to fail, ok");
    } else {
        ALOGE("RSA signature verification error");
        goto err3;
    }
    
    ret = 0;

err3:
    OPENSSL_free(sig);
err2:
    EVP_PKEY_CTX_free(ctx);
err1:
    return ret;
}

int
ec_sign_verify(EVP_PKEY *pKey)
{
    EC_KEY *eckey = NULL;
    unsigned char sha256[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    unsigned char *sig = NULL;
    unsigned int sigLen = 0;
    int ret = -1;

    eckey = EVP_PKEY_get1_EC_KEY(pKey);
    if (eckey == NULL) {
        ALOGE("EC EVP_PKEY_get1_EC_KEY error");
        goto err1;
    }

    /* Signing */
   
    sig = OPENSSL_malloc(ECDSA_size(eckey));
    if (!sig) {
        ALOGE("EC malloc error");
        goto err2;
    }

    ALOGI("EC Generating signature");

    if (!ECDSA_sign(0, sha256, sizeof(sha256), sig, &sigLen, eckey)) {
        ALOGE("EC signing error");
        goto err3;
    }

    /* optionally use ECDSA_do_sign(...) -> https://www.openssl.org/docs/man1.1.0/man3/ECDSA_sign.html */


    /* Verification */

    ALOGI("EC verify signature");

    if (ECDSA_verify(0, sha256, sizeof(sha256), sig, sigLen, eckey) != 1) {
        ALOGE("EC signature verification error");
        goto err3;
    }
    
    ALOGI("EC signature verification ok");
    
    sha256[2] = 1;
    if (ECDSA_verify(0, sha256, sizeof(sha256), sig, sigLen, eckey) == 0) {
        ALOGI("EC signature verification expected to fail, ok");
    } else {
        ALOGE("EC signature verification error");
        goto err3;
    }
    
    /* optionally use ECDSA_do_verify(...) -> https://www.openssl.org/docs/man1.1.0/man3/ECDSA_sign.html */

    ret = 0;

err3:
    OPENSSL_free(sig);
err2:
    EC_KEY_free(eckey);
err1:
    return ret;
}

int
rsa_sign_verify(EVP_PKEY *pKey)
{
    RSA *rsa = NULL;
    unsigned char message[] = {1,2,3};
    unsigned char *sig = NULL;
    unsigned int sigLen = 0;
    int ret = -1;

    rsa = EVP_PKEY_get1_RSA(pKey);
    if (rsa == NULL) {
        ALOGE("RSA EVP_PKEY_get1_RSA error");
        goto err1;
    }

    /* Signing */
   
    sig = OPENSSL_malloc(RSA_size(rsa));
    if (!sig) {
        ALOGE("RSA malloc error");
        goto err2;
    }

    ALOGI("RSA generating signature");

    if (!RSA_sign(RSA_PKCS1_PADDING, message, sizeof(message), sig, &sigLen, rsa)) {
        ALOGE("RSA signing error");
        goto err3;
    }

    /* Verification */

    ALOGI("RSA verify signature");

    if (!RSA_verify(RSA_PKCS1_PADDING, message, sizeof(message), sig, sigLen, rsa)) {
        ALOGE("RSA signature verification error");
        goto err3;
    }
    
    ALOGI("RSA signature verification ok");
    
    message[2] = 1;
    if (!RSA_verify(RSA_PKCS1_PADDING, message, sizeof(message), sig, sigLen, rsa)) {
        ALOGI("RSA signature verification expected to fail, ok");
    } else {
        ALOGE("RSA signature verification error");
        goto err3;
    }

    ret = 0;

err3:
    OPENSSL_free(sig);
err2:
    RSA_free(rsa);
err1:
    return ret;
}

int
rsa_evp_pkey_encrypt_decrypt(EVP_PKEY *pKey)
{
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char clear[] = {1,2,3};
    unsigned char *ciphered = NULL, *deciphered = NULL;
    size_t cipheredLen = 0, decipheredLen = 0, clearLen = 3;
    int ret = -1;

    ctx = EVP_PKEY_CTX_new(pKey, NULL);
    if (!ctx) {
        ALOGE("EVP_PKEY_CTX_new error");
        goto err1;
    }

    /* Encryption (RSA_PKCS1_PADDING) */

    if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_encrypt(ctx, NULL, &cipheredLen, clear, clearLen) <= 0) {
        ALOGE("Encryption init error");
        goto err2;
    }

    ciphered = OPENSSL_malloc(cipheredLen);
    if (!ciphered) {
        ALOGE("malloc error");
        goto err2;
    }

    ALOGI("Generating encryption blob");

    if (EVP_PKEY_encrypt(ctx, ciphered, &cipheredLen, clear, clearLen) <= 0) {
        ALOGE("Encryption error");
        goto err3;
    }

    /* Decryption (support only RSA_PKCS1_PADDING, https://github.com/tpm2-software/tpm2-tss-engine/pull/89) */

    if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_decrypt(ctx, NULL, &decipheredLen, ciphered, cipheredLen) <= 0) {
        ALOGE("Decryption init error");
        goto err2;
    }

    deciphered = OPENSSL_malloc(decipheredLen);
    if (!deciphered) {
        ALOGE("malloc error");
        goto err2;
    }
    
    memset(deciphered, 0, decipheredLen);

    ALOGI("Decrypting encrypted blob");

    if (EVP_PKEY_decrypt(ctx, deciphered, &decipheredLen, ciphered, cipheredLen) <= 0) {
        ALOGE("Decryption error");
        goto err3;
    }

    if((decipheredLen != clearLen) || (strncmp((const char *)clear, (const char *)deciphered, decipheredLen) != 0))
    {
        ALOGE("Decryption error, value not the same");
        goto err3;
    }

    ALOGI("Decryption verification ok");
    
    ret = 0;
    
err3:
    OPENSSL_free(ciphered);
    OPENSSL_free(deciphered);
err2:
    EVP_PKEY_CTX_free(ctx);
err1:
    return ret;
}

int
rsa_encrypt_decrypt(EVP_PKEY *pKey)
{
    RSA *rsa = NULL;
    unsigned char clear[] = {1,2,3};
    unsigned char *ciphered = NULL, *deciphered = NULL;
    int cipheredLen = 0, decipheredLen = 0, clearLen = 3;
    int ret = -1;

    rsa = EVP_PKEY_get1_RSA(pKey);
    if (rsa == NULL) {
        ALOGE("EVP_PKEY_get1_RSA error");
        goto err1;
    }

    /* Encrypt (RSA_PKCS1_OAEP_PADDING) */
   
    ciphered = OPENSSL_malloc(RSA_size(rsa));
    if (!ciphered) {
        ALOGE("malloc error");
        goto err2;
    }

    ALOGI("Generating encryption blob");

    cipheredLen = RSA_public_encrypt (clearLen, clear, ciphered, rsa, RSA_PKCS1_OAEP_PADDING);
    if (cipheredLen == -1) {
        ALOGE("Encryption error");
        goto err3;
    }

    /* Decrypt (RSA_PKCS1_OAEP_PADDING) */

    deciphered = OPENSSL_malloc(RSA_size(rsa));
    if (!deciphered) {
        ALOGE("malloc error");
        goto err2;
    }

    ALOGI("Decrypting encrypted blob");

    decipheredLen = RSA_private_decrypt(cipheredLen, ciphered, deciphered, rsa, RSA_PKCS1_OAEP_PADDING);
    if (decipheredLen == -1) {
        ALOGE("Decryption error");
        goto err3;
    }
    
    if((decipheredLen != clearLen) || (strncmp((const char *)clear, (const char *)deciphered, decipheredLen) != 0))
    {
        ALOGE("Decryption error, value not the same");
        goto err3;
    }
    
    ALOGI("Decryption verification ok");

    ret = 0;
    
err3:
    OPENSSL_free(ciphered);
    OPENSSL_free(deciphered);
err2:
    RSA_free(rsa);
err1:
    return ret;
}

void Java_com_ifx_nave_JavaNative_nativeHelloWorld(JNIEnv* env __unused, jobject obj __unused)
{
    (void) env;
    ALOGI("Invoked Java_com_ifx_nave_JavaNative_nativeHelloWorld");
    ALOGI("Exit Java_com_ifx_nave_JavaNative_nativeHelloWorld");
}

void Java_com_ifx_nave_JavaNative_nativeTestTPMEngine(JNIEnv* env __unused, jobject obj __unused)
{
    (void) env;

    ENGINE  *pEngine = NULL;
    EVP_PKEY *pRsaKey = NULL;
    EVP_PKEY *pEcKey = NULL;
  
    ALOGI("Invoked Java_com_ifx_nave_JavaNative_nativeTestTPMEngine");
  
    init_openssl();

    ENGINE_load_dynamic();
    pEngine = ENGINE_by_id("dynamic");
    if (!pEngine)
    {
        ALOGE("Unable to load dynamic engine.");
        goto err1;
    }

    if (!ENGINE_ctrl_cmd_string(pEngine, "SO_PATH", "/system/lib64/libtpm2tss.so", 0)
        || !ENGINE_ctrl_cmd_string(pEngine, "ID", "tpm2tss", 0)
        || !ENGINE_ctrl_cmd_string(pEngine, "LOAD", NULL, 0)) {
        ALOGE("Unable to load TPM OpenSSL engine ENGINE_ctrl_cmd_string.");
        goto err2;
    }

    if (!ENGINE_init(pEngine))
    {
        ALOGE("Unable to init TPM2 Engine.");
        goto err2;
    }

    if (!ENGINE_set_default(pEngine, ENGINE_METHOD_ALL))
    {
        ALOGE("Unable to set TPM2 Engine.");
        goto err2;
    }

#ifdef ENABLE_OPTIGA_TPM
    if (!ENGINE_ctrl(pEngine, ENGINE_CMD_BASE + 1, 0, "device:/dev/tpmrm0", NULL))
    {
        ALOGE("Unable to switch to TPM device mode (/dev/tpmrm0).");
#else
    if (!ENGINE_ctrl(pEngine, ENGINE_CMD_BASE + 1, 0, "mssim:host=localhost,port=2321", NULL))
    {
        ALOGE("Unable to switch to TPM simulator mode.");
#endif
        goto err2;
    }

    /* Generate TPM RSA key using tpm2-tss-engine library */
    if (rsa_genkey())
        goto err2;

    /* Generate TPM EC key using tpm2-tss-engine library */
    if (ec_genkey())
        goto err2;
    
    /* Load RSA Key */
    //pRsaKey = ENGINE_load_private_key(pEngine, "0x81000002", NULL, NULL);
    pRsaKey = ENGINE_load_private_key(pEngine, RSA_KEY_PATH, NULL, NULL);
    if (pRsaKey == NULL) {
        ALOGE("RSA Key loading error");
        goto err2;
    }
    ALOGI("Loaded RSA key");
    
    /* Load EC Key */
    pEcKey = ENGINE_load_private_key(pEngine, EC_KEY_PATH, NULL, NULL);
    if (pEcKey == NULL) {
        ALOGE("EC Key loading error");
        goto err2;
    }
    ALOGI("Loaded EC key");
    
    /* EC signing & verification */
    if (ec_evp_pkey_sign_verify(pEcKey))
        goto err3;
    if (ec_sign_verify(pEcKey))
        goto err3;
    
    /* RSA signing & verification */
    if (rsa_evp_pkey_sign_verify(pRsaKey))
        goto err3;
    if (rsa_sign_verify(pRsaKey))
        goto err3;

    /* RSA encryption & decryption */
    if (rsa_evp_pkey_encrypt_decrypt(pRsaKey))
        goto err3;
    if (rsa_encrypt_decrypt(pRsaKey))
        goto err3;

    ALOGI("Exit Java_com_ifx_nave_JavaNative_nativeTestTPMEngine");

err3:
    EVP_PKEY_free(pRsaKey);
    EVP_PKEY_free(pEcKey);
err2:
    ENGINE_free(pEngine);
err1:
    cleanup_openssl();

}

