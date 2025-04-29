/***********************************************************************************************
*  Personal Standalone AES-256-CBC File Encryptor
*  Author:        IslamiTP
*  Date:          19/04/2025
*  Language:      C (GCC Compiler)
*  Libraries:     OpenSSL (libcrypto)
*
*  Description:
*      A standalone file encryption and decryption program written in C, using OpenSSL's
*      EVP symmetric cryptography API. Supports password-based key derivation, optional salt,
*      and basic key/iv/salt visibility for debugging. 
*
*  Important:
*      - KEEP your password/key safe — without it, encrypted files cannot be recovered!
*      - This tool is standalone. Files must be decrypted using this tool itself.
*
*  Sources:
*      - OpenSSL Wiki (EVP Symmetric Encryption and Decryption)
*      - OpenSSL Documentation (EVP functions)
***********************************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>     
#include <stdbool.h>
#include <unistd.h>/* Unix/Linux Library */
/* The follow libraries are for 
-- high-level cryptographic functions */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>  
#include <openssl/rand.h> // for random


#define BUFFER_SIZE 1024
#define SALT_SIZE 8


typedef struct {    /* DefileInputing the data variables */
int encrypt;            /* 1 = encrypt, 0 = decrypt */
char *key;              /* password string */
int use_salt;           /* 1 = salt, 0 = salt */
int print_key_iv_salt;  /* 1 = print them, 0 = doesn't print them */
char *infile;           /* input file name */
char *outfile;          /* output file name */
} Opts;


// int argv_cnt = 1;
// helper function to handle any errors (using openssl library)
/* Source Code Was pulled from OpenSSL wiki EVP Symmetric Encryption and Decryption */
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

    /* Usage Instructions for user when cmd line was run incorrectly */
void print_help(char **argv)
{
    printf("use: %s -e|-d -k key -in input -out output\n", argv[0]);
    exit(1);
}


/* Message Encryption Process
    1. Create and configure the encryption context
    2. Initialize the encryption operation with the desired cipher
    3. Feed the plaintext data into the encryption function
    4. Finalize the encryption to retrieve any remaining output

    The EVP_CIPHER object used will be EVP_aes_256_cbc()

    Function prototype for encryption:
    int encrypt(plaintext, plaintext_length, key, iv)
*/
/* Source Code Was pulled from OpenSSL wiki EVP Symmetric Encryption and Decryption */
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key
            , unsigned char *iv, unsigned char *ciphertext)
{
    /* Declare encryption context structure */
    EVP_CIPHER_CTX *ctx; // Creates new encryption context

    int len; // Temp variable to hold length of encrypt data

    int ciphertext_len;
    
    /* Initialize cipher */
    if (!(ctx = EVP_CIPHER_CTX_new())) // Allocates memory and preps for encryption
        handleErrors();


    /*
        Initialize the encryption operation. IMPORTANT - ensure you use a key
        and iv size appropriate for your cipher
        we are using 256 bit AES (256 bit key).
        The iv size for most modes is the same as the block size. 
        For AES this is 128 bit
    */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) // Null is no custom engine (Hardware accelerators)
        handleErrors();


    /*
        Provide the message to be encrypted, and obtain the encrypted output.
        EVP_EncryptUpdate can be called multiple times if necessary 
    */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
            /* Called multiple times if data is chunked */
    
    /*
    * Finalize the encryption. Further ciphertext bytes may be written at
    * this stage.
    */      /* (PADDING) */    
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx); /* Frees the context for no memory leaks */

    return ciphertext_len;
}


/* Message Decryption Process
    1. Create and configure the decryption context
    2. Initialize the decryption operation with the desired cipher
    3. Feed the ciphertext data into the decryption function
    4. Finalize the decryption to retrieve any remaining output

    Function prototype for decryption:
    int decrypt(ciphertext, ciphertext_length, key, iv)
*/
/* Source Code Was pulled from OpenSSL wiki EVP Symmetric Encryption and Decryption */
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{   
    /* Declare encryption context structure */
    EVP_CIPHER_CTX *ctx;

    int len;
    
    int plaintext_len;

    /* Create and initialize the new encryption context*/
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
    * Initialise the decryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for most modes is the same as the block size. For AES this
    * is 128 bits
    */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
    * Provide the message to be decrypted, and obtain the plaintext output.
    * EVP_DecryptUpdate can be called multiple times if necessary.
    */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
    * Finalize the decryption. Further plaintext bytes may be written at
    * this stage. (PADDING)
    */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx); /* Once again like encrypt frees memory allocation of ctx */

    return plaintext_len;
}

// If we want to add salt or no salt
int derive_key_iv(const char *password, unsigned char *salt, unsigned char *key,
    unsigned char *iv, int use_salt){
    

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    // EVP_md5 is a message digest algorithm that produces a 128-bit hash from the given input
    const EVP_MD *dgst = EVP_md5();

    /* Sets if the program will use -salt or -nosalt */
    if (!use_salt) {
        salt = NULL; // EVP_BytesToKey will treat this as no salt
    }

    // EVP_BytesToKey is used to derive a cryptographic key and IV from a password and optional salt
    // Format: EVP_BytesToKey(cipher, digest, salt, password, password_len, iterations, out_key, out_iv)
    // This function ensures the key and IV are generated in a format compatible with OpenSSL’s expectations
    int key_iv_len = EVP_BytesToKey(
        cipher
        ,dgst
        ,salt
        ,(const unsigned char *)password
        ,strlen(password)
        ,1      //Iteration Count of digest, set as 1 for simple security
        ,key
        ,iv
    );

    // Validate Key size
    if (key_iv_len != 32) {
        fprintf(stderr, "Provided Key size is not 256 bits!\n");
        return 0;
    }
    return 1;
}


/* Command Line Parsing and Options */
int parse_args(int argc, char *argv[], Opts *opts) {
    /* Set defaults */
    opts->encrypt = -1;
    opts->key = NULL;
    opts->infile= NULL;
    opts->outfile = NULL;
    opts->use_salt = 0;
    opts->print_key_iv_salt = 0;

    /* Command Line Options */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0) {   /*  Sets Encrypting */
            opts->encrypt = 1; 
        } else if (strcmp(argv[i], "-d") == 0) {  /* Sets Decrypting */
            opts->encrypt = 0;
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {    /* Sets the key */
            opts->key = argv[++i];
        } else if (strcmp(argv[i], "-in") == 0 && i + 1 < argc) {   /* Sets the file input */
            opts->infile = argv[++i];
        } else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {  /* Sets the out file */
            opts->outfile = argv[++i];
        } else if (strcmp(argv[i], "-salt") == 0) {     /* Sets to use salt */
            opts->use_salt = 1;
        } else if (strcmp(argv[i], "-nosalt") == 0) {   /* Sets to not use salt */
            opts->use_salt = 0;
        } else if (strcmp(argv[i], "-p") == 0) {    /* Sets to print the key,iv, and salt */
            opts->print_key_iv_salt = 1;
        } else {             /* Throws error if not options were selected */
            fprintf(stderr, "This (%s) is not an option type 'help' for assistance!\n", argv[i]);
            return 0;
        }
}

/* Checking if the args are valid */
if (opts->encrypt == -1 || !opts->key || !opts->infile || !opts->outfile) {
    fprintf(stderr, "Missing required arguments\n");
    return 0;
}
return 1;    
}

/* Here everything comes together and builds the program */
int main(int argc, char *argv[]) {
/* Step 1: Parse command-line arguments */
Opts opts = {0};
if (!parse_args(argc, argv, &opts)) {
    print_help(argv);
    return 1;
}

    /* A 256 bit key */
    unsigned char key[32];
    /* A 128 bit IV */
    unsigned char iv[16];
    unsigned char salt[8] = {0};


    /* Step 2: If encrypting, it generates salt */
    if (opts.encrypt && opts.use_salt) {
        if (!RAND_bytes(salt, sizeof(salt))) {           /* Sets   Randomness to salt */
            fprintf(stderr, "Error generating salt.\n"); /* Throws error if not random */
            return 1;
        }
    }


    /* Step 3: Opens input file */
    FILE *fileInput = fopen(opts.infile,"rb");  
    if (!fileInput) {
        perror("Failed to open input file");
        return 1;
    }

    /* Reading input file to determine input file size */
    fseek(fileInput, 0, SEEK_END); 
    long inputText_len = ftell(fileInput); 
    fseek(fileInput, 0, SEEK_SET);

    /* Utilizing the memory allocation for file reading */
    unsigned char *inputText = malloc(inputText_len);
    fread(inputText, 1, inputText_len, fileInput);
    fclose(fileInput);



    /* Step 4: Derive key/iv (based on encryption or decryption) */
    unsigned char *decrypt_text = inputText;

    if (!opts.encrypt) {
        if (inputText_len > 16 && memcmp(inputText, "Salted__", 8) == 0) {
            memcpy(salt, inputText + 8, 8);
            if (!derive_key_iv(opts.key, salt, key, iv, 1)) {
                return 1;
            }
            decrypt_text = inputText + 16;
            inputText_len -= 16;
        } else {
            if (!derive_key_iv(opts.key, NULL, key, iv, 0)) {
                return 1;
            }
        }
    } else {
        if (!derive_key_iv(opts.key, salt, key, iv, opts.use_salt)) {
            return 1;
        }
    } 


    /* Step 4.5: (Optional) Print key/iv/salt */
    if (opts.print_key_iv_salt) {
        printf("Key: ");    for (int i = 0; i < 32; i++) printf("%02x", key[i]);        
        printf("\nIV: ");   for (int i = 0; i < 16; i++) printf("%02x", iv[i]);
        if (opts.use_salt) {
            printf("\nSalt: ");
            for (int i = 0; i < 8; i++) printf("%02x", salt[i]);
        }
        printf("\n");
    }


    /* Step 5: Allocate output and encrypt/decrypt */
    unsigned char *inputCipherText = malloc(inputText_len + EVP_MAX_BLOCK_LENGTH);
    int output_len = opts.encrypt;
            /* Allocates buffer for padding */
    if (opts.encrypt) {
        output_len = encrypt(inputText, inputText_len, key, iv, inputCipherText);
    }else {
        output_len = decrypt(decrypt_text, inputText_len, key, iv, inputCipherText);
    }


    /* STEP 6: Opens output file (encrypted file)*/
    FILE *fout = fopen(opts.outfile, "wb");
    if (!fout) {
        perror("Failed to open outputfile");
        free(inputText);
        free(inputCipherText);

        return 1;
    }


    /* Step 7: Writing Inputing Salt Header during Encryption */
    if (opts.encrypt) {
        if (opts.use_salt) {
            fwrite("Salted__", 1, 8, fout);        // OpenSSL salt prefix
            fwrite(salt, 1, 8, fout);              // 8-byte salt
        }        
    }
    fwrite(inputCipherText, 1, output_len, fout);   // Ciphertext
    fclose(fout);


    /* Step 8: Clear  */
    free(inputText);    
    free(inputCipherText);

    printf("Completed: Wrote %d bytes to %s\n", output_len, opts.outfile);

    /* Show the troll */
    printf("Decrypted text is: Dont worry about it\n");

    return 0;
}