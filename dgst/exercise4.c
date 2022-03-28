#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#define MAXBUF 1024

void handle_errors();

int main(int argc, const char *argv[]){
    FILE *fp;

    if(argc != 2){
        fprintf(stderr, "Error, invalid number of arguments\n");
        exit(1);
    }
    if (argv[1] == NULL){
        fprintf(stderr, "Error with the argument\n");
        exit(1);
    }
    if ((fp = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "File open error\n");
        exit(1);
    }

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    EVP_MD_CTX *md256 = EVP_MD_CTX_new();
    EVP_MD_CTX *md512 = EVP_MD_CTX_new();
    
    if(!EVP_DigestInit(md256, EVP_sha256()))
        handle_errors;
    if(!EVP_DigestInit(md512, EVP_sha512()))
        handle_errors;
    
    int n_read;
    unsigned char buffer[MAXBUF];
    while((n_read = fread(buffer, sizeof(char), MAXBUF, fp)) > 0){
    // Returns 1 for success and 0 for failure.
        if(!EVP_DigestUpdate(md256, buffer, n_read))
            handle_errors();
        if(!EVP_DigestUpdate(md512, buffer, n_read))
            handle_errors();
    }

    fclose(fp);
    
    unsigned char md256_value[EVP_MD_size(EVP_sha256())];
    unsigned char md512_value[EVP_MD_size(EVP_sha512())];
    unsigned char md512_h[EVP_MD_size(EVP_sha512())/2];
    unsigned char md512_l[EVP_MD_size(EVP_sha512())/2];
    unsigned char res[EVP_MD_size(EVP_sha512())/2];
    unsigned int md256_len, md512_len;

    //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
    if(!EVP_DigestFinal_ex(md256, md256_value, &md256_len))
        handle_errors();

    if(!EVP_DigestFinal_ex(md512, md512_value, &md512_len))
        handle_errors();

    // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
	EVP_MD_CTX_free(md256);
    EVP_MD_CTX_free(md512);

    printf("The digest (sha256) is: ");
    for(int i = 0; i < md256_len; i++)
		printf("%02x", md256_value[i]);
    printf("\n");

    printf("The digest (sha512) is: ");
    for(int i = 0; i < md512_len; i++)
		printf("%02x", md512_value[i]);
    printf("\n");
    
    printf("the digest high is: ");

    for(int i=0 ;i<md512_len/2; i++){
        md512_h[i] = md512_value[i];
        printf("%02x", md512_h[i]);
    }

    printf("\n");
    
    printf("the digest low is: ");

    for(int i=md256_len ;i < md512_len; i++){
        md512_l[i - md256_len] = md512_value[i];
        printf("%02x", md512_l[i - md256_len]);
    }

    printf("\n");
    unsigned char and[EVP_MD_size(EVP_sha512())/2];    
    printf("And is: \n");
    for(int i = 0; i< md256_len; i++){
        and[i] = (md512_l[i] & md512_h[i]);
        printf("%02x", and[i]);
        res[i] = md256_value[i] ^ and[i]; 
    }
    printf("\n");

    printf("The result is: ");
    for(int i = 0; i < md256_len; i++)
		printf("%02x", res[i]);
    printf("\n");

    return 0;

}

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}
