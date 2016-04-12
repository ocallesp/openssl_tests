#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>


static const char *cert_filename = "cert.pem";

void verify_file(const char *data_filename);
void verify_signature(FILE *fp_data, EVP_PKEY *pkey, FILE *fp_sig);
static char * get_signature_filename(const char *data_filename);
static void create_signature(FILE *fp_data, EVP_PKEY *pkey, FILE *fp_sig);

int main(int argc, char **argv)
{
    const char *data_filename = "archivo.txt";

    ERR_load_crypto_strings();

    if (argc == 2) {
        data_filename = argv[1];
    }

    verify_file(data_filename);

    exit(0);
}

void verify_file(const char *data_filename)
{
    FILE *fp_pubkey = NULL;
    FILE *fp_data = NULL;
    FILE *fp_sig = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    

    char *signature_filename = get_signature_filename(data_filename);
    printf("signature file: %s\n", signature_filename);

    fp_sig = fopen(signature_filename, "r");
    if (!fp_sig) {
        fprintf(stderr, "Failed fopen %s\n", signature_filename);
        exit(1);
    }

    /* Read public key */
    fp_pubkey = fopen(cert_filename, "r");
    if (!fp_pubkey) {
        fprintf(stderr, "Failed fopen %s\n", cert_filename);
        exit(1);
    }

    x509 = PEM_read_X509(fp_pubkey, NULL, NULL, NULL);
    if (!x509) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    pkey = X509_get_pubkey(x509);
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* read data from file */
    fp_data = fopen(data_filename, "r");
    if (!fp_data) {
        fprintf(stderr, "Failed fopen %s\n", data_filename);
        exit(1);
    }

    verify_signature(fp_data, pkey, fp_sig);

    free(signature_filename);
    fclose(fp_pubkey);
    fclose(fp_data);
    fclose(fp_sig);
}

char * get_signature_filename(const char *data_filename)
{
    char *signature_filename = NULL;

    size_t len = strlen(data_filename);
    signature_filename = (char *)malloc(len + 8);

    strncpy(signature_filename, data_filename, len+1);
    strcat(signature_filename, ".signed");
    
    return signature_filename;
}


#define BUFFER_SIZE   4096
void verify_signature(FILE *fp_data, EVP_PKEY *pkey, FILE *fp_sig)
{
    char buffer[BUFFER_SIZE];  
    unsigned char sig_buffer[BUFFER_SIZE];
    EVP_MD_CTX md_ctx;

    size_t sig_len = fread(sig_buffer, 1, BUFFER_SIZE, fp_sig);
    printf("size of signature: %d\n", sig_len);


    /* get size of file */
    fseek(fp_data, 0, SEEK_END);
    size_t data_size = ftell(fp_data);
    fseek(fp_data, 0, SEEK_SET);

    if (!EVP_VerifyInit(&md_ctx, EVP_sha256())) {
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

        if (!EVP_VerifyUpdate(&md_ctx, buffer, len)) {
            ERR_print_errors_fp(stderr);
            exit(1);
        }
        bytes_left -= len;
    }

    /* Do the signature */
    if (!EVP_VerifyFinal(&md_ctx, sig_buffer, sig_len, pkey)) {
        ERR_print_errors_fp(stderr);
        exit(1);
    } else {
        printf("Correct signature\n");
    }


    /* clean everything */
    EVP_PKEY_free(pkey);
}
