#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#define ENCRYPT 1
#define DECRYPT 0
#define MAX_ENC_LEN 1000000
#define MAX_BUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, const char *argv[])
{
    if (argc != 3){
        fprintf(stderr, "Error, invalid number of arguments\n");
        exit(EXIT_FAILURE);   
    }

    FILE *fin;
    if ((fin = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "Error, file open failed\n");
        exit(EXIT_FAILURE);
    }
    
    const EVP_CIPHER *algorithm; 
    algorithm = EVP_get_cipherbyname(argv[2]);

    if (algorithm == NULL){
        // Actually the function returns NULL for algorithms such as "AES-128-SIV", "AES-128-CBC-CTS" and "CAMELLIA-128-CBC-CTS" as well, which were previously only accessible via low level interfaces.
        fprintf(stderr, "Error, invalid cipher algorithm\n"); 
        exit(EXIT_FAILURE);
    }

    unsigned char key[] = "0123456789ABCDEF";
    unsigned char iv[]  = "1111111111111111";

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    // pedantic mode: check NULL
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(!EVP_CipherInit(ctx, algorithm, key, iv, ENCRYPT))
        handle_errors();
    
    unsigned char ciphertext[MAX_ENC_LEN];

    int update_len, final_len;
    int ciphertext_len=0;
    int n_read;
    unsigned char buffer[MAX_BUFFER];


    while((n_read = fread(buffer, 1, MAX_BUFFER, fin)) > 0){
        if(ciphertext_len > MAX_ENC_LEN - n_read - EVP_CIPHER_CTX_block_size(ctx)){ //use EVP_CIPHER_get_block_size with OpenSSL 3.0+
            fprintf(stderr,"The file to cipher is larger than I can\n");
            abort();
        }
    
        if(!EVP_CipherUpdate(ctx,ciphertext+ciphertext_len,&update_len,buffer,n_read))
            handle_errors();
        ciphertext_len+=update_len;
    }

    if(!EVP_CipherFinal_ex(ctx,ciphertext+ciphertext_len,&final_len))
        handle_errors();

    ciphertext_len+=final_len;

    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext lenght = %d\n", ciphertext_len);
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();

    return 0;
}
