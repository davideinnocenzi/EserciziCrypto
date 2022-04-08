#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

#define MAXBUF 1024
#define NBIT 256
#define NBYTE 32

void handleErrors(){
    FILE *err = fopen("err.txt", "w");
    if(err == NULL){
        abort();
    }
    ERR_print_errors_fp(err);
    fclose(err);
    printf("\n");
    abort();
}

int main (int argc, char**argv){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    FILE* fp;

    if(argc != 3){
        printf("ERROR In parameters. USAGE: %s key file", argv[0]);
        exit(1);
    }

    if((fp = fopen(argv[2], "r"))== NULL){
        printf("ERROR in file pointer");
        exit(1);
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_DigestInit(ctx,EVP_sha256());
    unsigned char opad=0x5c;
    unsigned char ipad=0x36;

    unsigned char opad_final[NBYTE];
    unsigned char ipad_final[NBYTE];
    bzero(ipad_final,NBYTE);
    bzero(opad_final,NBYTE);

    for(int i=0; i< NBYTE;i++){
        opad_final[i] = opad;
        ipad_final[i] = ipad;
    }

    int key_size = strlen(argv[1]);
    unsigned char padded_key[NBYTE];

    int dest_size;
    bzero(padded_key,NBYTE);

    if(key_size <= NBYTE){
        strcpy(padded_key,argv[1]);
    }

    if(key_size > NBYTE){
        if(!EVP_DigestUpdate(ctx,argv[1],key_size))
            handleErrors();
        if(!EVP_DigestFinal(ctx, padded_key, &dest_size))
            handleErrors();
    }

    // EVP_MD_CTX_free(ctx);

    // EVP_MD_CTX *ctx1 = EVP_MD_CTX_new();
    // EVP_MD_CTX_init(ctx1);
    EVP_DigestInit_ex(ctx, EVP_sha256(),NULL);

    unsigned char xor_ipad[NBYTE];
    unsigned char xor_opad[NBYTE];

    for(int i=0;i< NBYTE; i++){

        xor_ipad[i] = padded_key[i] ^ ipad_final[i];
        xor_opad[i] = padded_key[i] ^ opad_final[i];
    
    }
    size_t n_read;
    unsigned char buffer[NBYTE];

    while((n_read = fread(buffer, sizeof(char), NBYTE, fp)) > 0){
    // Returns 1 for success and 0 for failure.
        
        if(!EVP_DigestUpdate(ctx, xor_ipad, strlen(xor_ipad)))
            handleErrors();

        if(!EVP_DigestUpdate(ctx, buffer, NBYTE))
            handleErrors();
    }

    unsigned char inner_hash[NBYTE];
    int inner_size;
    if(!EVP_DigestFinal(ctx,inner_hash,&inner_size))
        handleErrors();

    // EVP_MD_CTX_free(ctx1);

    // EVP_MD_CTX *ctx2 = EVP_MD_CTX_new();
    // EVP_MD_CTX_init(ctx2);

    EVP_DigestInit(ctx,EVP_sha256());

    // if(!EVP_DigestInit(ctx2, EVP_sha256()))
    //     handleErrors();
    
    if(!EVP_DigestUpdate(ctx,xor_opad,strlen(xor_opad)))
        handleErrors();
    
    if(!EVP_DigestUpdate(ctx,inner_hash,inner_size))
        handleErrors();
    
    unsigned char hmac[NBYTE];
    int hmac_len;

    if(!EVP_DigestFinal(ctx,hmac,&hmac_len))
        handleErrors();
    
    EVP_MD_CTX_free(ctx);
    ERR_free_strings();
    fclose(fp);
    CRYPTO_cleanup_all_ex_data();

    printf("The hmac of the file %s is: ", argv[2]);
    for(int i = 0; i < hmac_len; i++)
		printf("%02x", hmac[i]);
    printf("\n");
}