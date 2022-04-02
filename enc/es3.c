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
    if (argc != 2){
        fprintf(stderr, "Error, invalid number of arguments\n");
        exit(EXIT_FAILURE);   
    }

    FILE *fin;
    if ((fin = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "Error, file open failed\n");
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

    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))
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

    // Create a 128 bit mask (16 bytes)
    unsigned char ascii_mask[] = "ffffffffffffffffffffffffffffffff"; // all ones
    unsigned char mask[16];
    for(int i = 0; i < strlen(ascii_mask)/2;i++)
        sscanf(&ascii_mask[2*i],"%2hhx", &mask[i]);

    for(int i = 0; i < 16; i++)
        ciphertext[i] ^= mask[i];    // Apply the XOR mask for the first 16 bytes of the cyphertext
    

    printf("'Dirty' Ciphertext:\n");
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    // Decrypt the new cyphertext
    
    EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(dec_ctx,EVP_aes_128_cbc(), key, iv, DECRYPT);

    unsigned char decrypted[ciphertext_len]; //may be larger than needed due to padding

    update_len = 0;
    final_len = 0;
    int decrypted_len=0;
    EVP_CipherUpdate(dec_ctx, decrypted, &update_len, ciphertext, ciphertext_len);
    decrypted_len+=update_len;

    EVP_CipherFinal_ex(dec_ctx, decrypted+decrypted_len, &final_len);
    decrypted_len+=final_len;

    EVP_CIPHER_CTX_free(dec_ctx);

    printf("Plaintext lenght = %d\n",decrypted_len);
    for(int i = 0; i < decrypted_len; i++)
        printf("%c", decrypted[i]);
    printf("\n");

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();

    return 0;
}
