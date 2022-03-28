#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

#define MAXBUF 1024

void handleErrors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main (int argc, char**argv){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    unsigned char key[] = "deadbeefdeadbeef"; 

    if(argc !=3 ){
        printf("ERROR in parameters");
        exit(1);
    }

    if(argv[1] == NULL){
        printf("ERROR in first parameter");
        exit(1);
    }

    if(argv[2] == NULL){
        printf("ERROR in second parameter");
        exit(1);
    }

    FILE* fp;

    if(((fp = fopen(argv[2],"r")) == NULL)){
        handleErrors();
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY *hkey;

    hkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC,NULL,key,16);
    
    if(!EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, hkey)){
        handleErrors();
    }

    unsigned char buffer[MAXBUF];
    size_t n;

    while ((n = fread(buffer,1,MAXBUF,fp)) > 0){
       if(!EVP_DigestSignUpdate(ctx, buffer, n))
        handleErrors();
    }

    fclose(fp);

    unsigned char hmac_calc[EVP_MD_size(EVP_sha256())];
    unsigned char hmac_in[EVP_MD_size(EVP_sha256())];
    size_t hmac_len;

    if(!EVP_DigestSignFinal(ctx,hmac_calc,&hmac_len)){
        handleErrors();
    }

    printf("HMAC is: ");

    for(int i = 0; i < hmac_len; i++)
	     printf("%02x", hmac_calc[i]);
    printf("\n");


    for(int i = 0; i< strlen(argv[1])/2; i++){
        sscanf(&argv[1][i*2],"%2hhx",&hmac_in[i]);
    }

    if(CRYPTO_memcmp(hmac_calc,hmac_in,hmac_len) == 0){
        printf("HMAC are equal!\n");
    }   else{
        printf("HMAC are not equal!\n");
    }
    printf("\n");

    EVP_MD_CTX_free(ctx);
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
    return 0;


}