#pragma once
#include "./types/keys.h"
#include <stdint.h>
#include <stdio.h>

//* Square-and-multiply algorithm, crypts/encrypts number
uint64_t exponentAndMod(uint64_t num, uint64_t exponent, char binExponent[64],
  short binExpNumberOfBits, uint64_t mod);

//* Encrypt *.txt already exists and write to different file
void encryptTxt(char* initialFileName, char* encryptedFileName,
  struct Key* public, uint64_t n);

//* Decrypt ciphertext from *.txt to different file
void decryptTxt(char* encryptedFileName, char* decryptedFileName,
  struct Key* private, uint64_t n);

//* Create digital signature for a message using private key
uint64_t signMessage(uint64_t message, struct Key* private, uint64_t n);

//* Verify digital signature using public key
int verifySignature(uint64_t message, uint64_t signature, struct Key* public, uint64_t n);
