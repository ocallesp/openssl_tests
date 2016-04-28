#include <stdio.h>
#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>


static FILE *fp_privkey = NULL;
static FILE *fp_sig = NULL;
static EVP_PKEY *pkey = NULL;
static const char *privatekey_filename = "swupd.server.key.pass.pem";
static const char pass[] = "swupd";
bool enable_signing = true;
bool initialized = false;

bool signature_initialize(void);
bool signature_terminate(void);
void signature_sign(const char *data_filename);
static char * get_signature_filename(const char *data_filename);
static void create_signature(FILE *fp_data);
void add_ciphers(void);

int main(int argc, char **argv)
{
    const char *data_filename = "archivo.txt";

    if (argc == 2) {
        data_filename = argv[1];
    }

    if (!signature_initialize()) {
        printf("Can't initialize the crypto signature module!\n");
        goto exit;
    }

    signature_sign(data_filename);

    signature_terminate();
exit:
    exit(0);
}

bool signature_initialize(void)
{
    if (!enable_signing) {
        return false;
    }

//    OpenSSL_add_all_algorithms();
//    OpenSSL_add_all_ciphers();
    add_ciphers();
    ERR_load_crypto_strings();

    /* Read private key */
    fp_privkey = fopen(privatekey_filename, "r");
    if (!fp_privkey) {
        fprintf(stderr, "Failed fopen %s\n",privatekey_filename);
        exit(1);
    }

    //pkey = PEM_read_PrivateKey(fp_privkey, NULL, NULL, NULL);
    pkey = PEM_read_PrivateKey(fp_privkey, NULL, NULL, (void *)pass);
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    initialized = true;

    return true;
}

bool signature_terminate(void)
{
    if (!enable_signing) {
        return false;
    }

    fclose(fp_privkey);
    fclose(fp_sig);

    fp_privkey = NULL;
    fp_sig = NULL;

    initialized = false;

    /* frees up the private key */
    EVP_PKEY_free(pkey);
    /* removes all ciphers and digests from the table */
    EVP_cleanup();
}

void signature_sign(const char *data_filename)
{
    FILE *fp_data = NULL;
    

    char *signature_filename = get_signature_filename(data_filename);
    printf("signature file: %s\n", signature_filename);


    /* read data from file */
    fp_data = fopen(data_filename, "r");
    if (!fp_data) {
        fprintf(stderr, "Failed fopen %s\n", data_filename);
        exit(1);
    }

    fp_sig = fopen(signature_filename, "w");
    if (!fp_sig) {
        fprintf(stderr, "Failed fopen %s\n", signature_filename);
        exit(1);
    }

    create_signature(fp_data);

    free(signature_filename);
    fclose(fp_data);
}

char * get_signature_filename(const char *data_filename)
{
    char *signature_filename = NULL;
    size_t len = 0;
    
    len = strlen(data_filename);
    signature_filename = (char *)malloc(len + 8);
    sprintf(signature_filename,"%s.signed", data_filename);   

    return signature_filename;
}


#define BUFFER_SIZE   4096
void create_signature(FILE *fp_data)
{
    char buffer[BUFFER_SIZE];  
    unsigned char sig_buffer[4096];
    int sig_len;
    EVP_MD_CTX md_ctx;

    /* get size of file */
    fseek(fp_data, 0, SEEK_END);
    size_t data_size = ftell(fp_data);
    fseek(fp_data, 0, SEEK_SET);

    /* replace EVP_sha1 by EVP_sha256 */
    if (!EVP_SignInit(&md_ctx, EVP_sha256())) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* read all bytes from file to calculate digest using sha1 and then sign it */
    size_t len = 0;
    size_t bytes_left = data_size;
    while (bytes_left > 0) {
        const size_t count = (bytes_left > BUFFER_SIZE ? BUFFER_SIZE : bytes_left);
        len = fread(buffer, 1, count, fp_data);
        if (len != count) {
            fprintf(stderr, "Failed len!= count\n");
            exit(1);
        }

        if (!EVP_SignUpdate(&md_ctx, buffer, len)) {
            ERR_print_errors_fp(stderr);
            exit(1);
        }
        bytes_left -= len;
    }

    /* Do the signature */
    if (!EVP_SignFinal(&md_ctx, sig_buffer, &sig_len, pkey)) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    size_t sig_len_tmp = fwrite(sig_buffer, 1, sig_len, fp_sig);
    if (sig_len_tmp != sig_len) {
        fprintf(stderr, "Failed fwrite sign file\n");
        exit(1);
    }

}


void add_ciphers(void)
{
    EVP_add_cipher(EVP_des_cfb());
    EVP_add_cipher(EVP_des_cfb1());
    EVP_add_cipher(EVP_des_cfb8());
    EVP_add_cipher(EVP_des_ede_cfb());
    EVP_add_cipher(EVP_des_ede3_cfb());
    EVP_add_cipher(EVP_des_ede3_cfb1());
    EVP_add_cipher(EVP_des_ede3_cfb8());

    EVP_add_cipher(EVP_des_ofb());
    EVP_add_cipher(EVP_des_ede_ofb());
    EVP_add_cipher(EVP_des_ede3_ofb());

    EVP_add_cipher(EVP_desx_cbc());
    EVP_add_cipher_alias(SN_desx_cbc, "DESX");
    EVP_add_cipher_alias(SN_desx_cbc, "desx");

    EVP_add_cipher(EVP_des_cbc());
    EVP_add_cipher_alias(SN_des_cbc, "DES");
    EVP_add_cipher_alias(SN_des_cbc, "des");
    EVP_add_cipher(EVP_des_ede_cbc());
    EVP_add_cipher(EVP_des_ede3_cbc());
    EVP_add_cipher_alias(SN_des_ede3_cbc, "DES3");
    EVP_add_cipher_alias(SN_des_ede3_cbc, "des3");

    EVP_add_cipher(EVP_des_ecb());
    EVP_add_cipher(EVP_des_ede());
    EVP_add_cipher(EVP_des_ede3());
    EVP_add_cipher(EVP_des_ede3_wrap());
    EVP_add_cipher_alias(SN_id_smime_alg_CMS3DESwrap, "des3-wrap");
}
