#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <string.h>   
#include "sodium.h"


void handleErrors(void)
    {
    unsigned long errCode;

    printf("An error occurred\n");
    while(errCode = ERR_get_error())
    {
        char *err = ERR_error_string(errCode, NULL);
        printf("%s\n", err);
    }
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len,unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext)
    {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();


    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(plaintext)
    {
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();

        ciphertext_len = len;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in cbc mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext)
    {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(ciphertext)
    {
        if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();

        plaintext_len = len;
    }

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    if(ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}
int main(int arc, char *argv[])
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();     
    /* A 256 bit key */
     FILE *file_key;
    file_key=fopen("private.key","rb");
    if(file_key==NULL){
        exit(EXIT_FAILURE);
    }

    unsigned char key[500];
    while(fgets(key,500,file_key));
    fclose(file_key); 

    /* A 128 bit IV */
    static unsigned char iv[128];
    if (sodium_init() < 0) return 1;
     randombytes_buf(iv, 128);;

    /* Message to be encrypted */
    
    FILE *file;
    file=fopen("prueba.txt","rb");
    if(file==NULL){
        exit(EXIT_FAILURE);
    }

    unsigned char plaintext[500];
    while(fgets(plaintext,500,file));
    fclose(file);   

    

    /* Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, dependant on the
     * algorithm and mode
     */
    unsigned char ciphertext[500];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[500];

    int decryptedtext_len = 0, ciphertext_len = 0;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt(plaintext, strlen(plaintext), key, iv, ciphertext);
    
    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, ciphertext, ciphertext_len);
    /*Rewrite de file with the encrypthed data*/
    FILE *file_enc;
    file_enc=fopen("pruebaC.txt","wb");
    fprintf(file_enc,"%s\n",ciphertext);
    fclose(file_enc);
    /* Message to be decrypted */
    
    FILE *file2;
    file2=fopen("pruebaC.txt","rb");
    if(file2==NULL){
        exit(EXIT_FAILURE);
    }
    
    unsigned char encryptedtext[500];
    while(fgets(encryptedtext,500,file2));
    fclose(file2); 

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

    if(decryptedtext_len < 0)
    {
        /* Verify error */
        printf("Decrypted text failed to verify\n");
    }
    else
    {
        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';

        /* Show the decrypted text */
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);
    }

    /* Remove error strings */
    ERR_free_strings();

    return 0;
}
