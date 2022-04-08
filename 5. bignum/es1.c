#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#define MAX_BYTES 32

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main (int argc, const char *argv[]){
    // Generate random string
     
    unsigned char rs1[MAX_BYTES];
    unsigned char rs2[MAX_BYTES];
    unsigned char rs3[MAX_BYTES];

    if (RAND_load_file("/dev/random", 64) != 64)
        handle_errors();

    if (RAND_bytes(rs1, MAX_BYTES) != 1)
        handle_errors(); 
    
    if (RAND_bytes(rs2, MAX_BYTES) != 1)
        handle_errors(); 
    
    if (RAND_bytes(rs3, MAX_BYTES) != 1)
        handle_errors(); 

    printf("rs1 :\n");
    for(int i=0; i < MAX_BYTES; i++)
        printf("%02x", rs1[i]);
    printf("\n");

    printf("rs2 :\n");
    for(int i=0; i < MAX_BYTES; i++)
        printf("%02x", rs2[i]);
    printf("\n");

    printf("rs3 :\n");
    for(int i=0; i < MAX_BYTES; i++)
        printf("%02x", rs3[i]);
    printf("\n\n");

    BIGNUM *bn1 = BN_new();
    BIGNUM *bn2 = BN_new();
    BIGNUM *bn3 = BN_new();
    
    printf("bn1 :\n");
    BN_bin2bn(rs1, MAX_BYTES, bn1);
    BN_print_fp(stdout, bn1);

    printf("\nbn2 :\n");
    BN_bin2bn(rs2, MAX_BYTES, bn2);
    BN_print_fp(stdout, bn2);
    printf("\nbn3 :\n");

    BN_hex2bn(&bn3, rs3);
    BN_bin2bn(rs3, MAX_BYTES, bn3);
    printf("\n\n");

    // Sum bn1 + bn2
    BIGNUM *sum = BN_new();
    BN_add(sum, bn1, bn2);

    printf("bn1 + bn2 = \n");
    BN_print_fp(stdout, sum);
    printf("\n");

    BN_free(sum);

    // Difference bn1 - bn3
    BIGNUM *difference = BN_new();
    BN_sub(difference, bn1, bn3);

    printf("bn1 - bn3 = \n");
    BN_print_fp(stdout, difference);
    printf("\n");

    BN_free(difference);
    
    BN_CTX *ctx = BN_CTX_new();

    // Multiplication bn1 * bn2 * bn3
    BIGNUM *multiplication = BN_new();
    BN_mul(multiplication, bn1, bn2, ctx);
    BN_mul(multiplication, multiplication, bn3, ctx);

    printf("bn1 * bn2 * bn3 = \n");
    BN_print_fp(stdout, multiplication);
    printf("\n");

    BN_free(multiplication);   

    // Integer division bn3 / bn1
    BIGNUM *division = BN_new();
    BIGNUM *reminder = BN_new();
    BN_div(division, reminder, bn1, bn2, ctx);
    printf("bn3 / bn1 = \n");
    BN_print_fp(stdout, division);
    printf("\nreminder = \n");
    BN_print_fp(stdout, reminder);
    printf("\n");

    BN_free(division);
    BN_free(reminder); 

    // Modulus bn1 % bn2
    BIGNUM *modulus = BN_new();
    BN_mod(modulus, bn1, bn2, ctx);
    printf("bn1 %% bn2 \n");
    BN_print_fp(stdout, modulus);
    printf("\n");
    BN_free(modulus); 

    // Modulus-exponentiation (bn1 ^ bn3) % bn2
    BIGNUM *modexp = BN_new();
    BN_mod_exp(modexp, bn1, bn3, bn2, ctx);
    printf("(bn1 ^ bn3) %% bn2 \n");
    BN_print_fp(stdout, modexp);
    printf("\n");
    BN_free(modexp);

    BN_free(bn1);
    BN_free(bn2);
    BN_free(bn3);

    return 0;
}
