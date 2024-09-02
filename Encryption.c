#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h> // for encrypt/decrypt process
#include <openssl/err.h> // for error handling

#define AES_256_KEY_SIZE 32  // 32 * 8 = 256 bits
#define AES_BLOCK_SIZE 16     // Block size for AES

void ErrorCutOut(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Create a new encryption context from the library
    int length;
    int ciphertext_length;

    if (!ctx) // Check if the context was successfully created
    {
        fprintf(stderr, "Error: Failed to create context\n"); // Report the error
        return -1; // Return error code to indicate failure
    }

    // Initialize the encryption operation with AES-256-CBC algorithm, key, and IV
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
    {
        fprintf(stderr, "Error: Encryption initialization failed\n");
        EVP_CIPHER_CTX_free(ctx); // Clean up context
        return -1;
    }

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_len) != 1)
    {
        fprintf(stderr, "Error: Encryption update failed\n"); // Report the error
        EVP_CIPHER_CTX_free(ctx); // Clean up allocated context
        return -1;
    }
    ciphertext_length = length; // store the length of the encrypted data

    // Finalize the encryption and add any remaining bytes
    if (EVP_EncryptFinal_ex(ctx, ciphertext + length, &length) != 1)
    {
        fprintf(stderr, "Error: Encryption finalization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_length += length; // Add the length of the final block to the total ciphertext length

    EVP_CIPHER_CTX_free(ctx); // Free the encryption context
    return ciphertext_length; // Return the length of the ciphertext
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Create a new decryption context from the library
    int length;
    int plaintext_length;

    if (!ctx) // Check if the context was successfully created
    {
        fprintf(stderr, "Error: Failed to create context\n"); // Report the error
        return -1;
    }

    // Initialize the decryption operation with AES-256-CBC algorithm, key, and IV
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
    {
        fprintf(stderr, "Error: Decryption initialization failed\n"); // Report the error
        EVP_CIPHER_CTX_free(ctx); // Clean up allocated context
        return -1;
    }

    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_len) != 1)
    {
        fprintf(stderr, "Error: Decryption update failed\n"); // Report the error
        EVP_CIPHER_CTX_free(ctx); // Clean up allocated context
        return -1;
    }
    plaintext_length = length; // Store the length of the decrypted data

    // Finalize the decryption and retrieve any remaining plaintext
    if (EVP_DecryptFinal_ex(ctx, plaintext + length, &length) != 1)
    {
        fprintf(stderr, "Error: Decryption finalization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_length += length; // Add the length of the final block to the total plaintext length

    EVP_CIPHER_CTX_free(ctx); // Free the decryption context
    return plaintext_length;
}

int main()
{
    char mode[10];
    char input_filename[256];
    char output_filename[256];
    unsigned char key[AES_256_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    int valid = 0;

    // Get mode (encrypt/decrypt) with validation
    do
    {
        printf("Enter mode (encrypt/decrypt): ");
        scanf("%9s", mode);

        // Convert to lowercase
        for (int i = 0; mode[i]; i++)
        {
            mode[i] = tolower(mode[i]);
        }

        if (strcmp(mode, "encrypt") == 0 || strcmp(mode, "decrypt") == 0)
        {
            valid = 1;
        }
        else
        {
            printf("Invalid mode. Please enter encrypt or decrypt.\n");
        }

    } while (!valid);

    // Get input file name, output file name, and encryption key
    printf("Enter input file name: ");
    scanf("%255s", input_filename);
    printf("Enter output file name: ");
    scanf("%255s", output_filename);
    printf("Enter encryption key (32 characters)*classified: ");
    scanf("%32s", (char *)key);

    // Initialize the IV with zeros (or use a fixed value)
    memset(iv, 0x00, AES_BLOCK_SIZE);

    // Read the input file
    FILE *input_file = fopen(input_filename, "rb");
    if (!input_file)
    {
        perror("Error opening input file");
        return 1;
    }

    fseek(input_file, 0, SEEK_END);
    long input_len = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    unsigned char *input_data = (unsigned char *)malloc(input_len);
    if (!input_data)
    {
        perror("Error allocating memory for input data");
        fclose(input_file);
        return 1;
    }

    fread(input_data, 1, input_len, input_file);
    fclose(input_file);

    unsigned char *output_data = (unsigned char *)malloc(input_len + EVP_MAX_BLOCK_LENGTH);
    if (!output_data)
    {
        perror("Error allocating memory for output data");
        free(input_data);
        return 1;
    }

    int output_len = 0;
    //mode select and check key 
    if (strcmp(mode, "encrypt") == 0)
    {
        output_len = encrypt(input_data, input_len, key, iv, output_data);
    }
    else if (strcmp(mode, "decrypt") == 0)
    {
        output_len = decrypt(input_data, input_len, key, iv, output_data);
        if (output_len < 0)
        {
            fprintf(stderr, "Decryption failed\n");
            free(input_data);
            free(output_data);
            return 1;
        }
    }

    // Write the output file
    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file)
    {
        perror("Error opening output file");
        free(input_data);
        free(output_data);
        return 1;
    }

    fwrite(output_data, 1, output_len, output_file);
    fclose(output_file);

    free(input_data);
    free(output_data);

    printf("Operation %s completed successfully.\n", mode);

    return 0;
}
