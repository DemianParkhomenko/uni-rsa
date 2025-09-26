/*
2021/2022
ТР-14
Пархоменка Дем'яна
Курсова робота на тему:"Шифрування даних методом RSA"
*/
#include "../tests/integration-test.h"
#include "./types/keys.h"
#include "crypto.h"
#include "key-gen.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

char* INITIAL_FILE_PATH = "./txt/initial.txt";
char* ENCRYPTED_FILE_PATH = "./txt/encrypted.txt";
char* DECRYPTED_FILE_PATH = "./txt/decrypted.txt";

#define runTest 1

int main() {
  if (runTest == 1) {
    integrationTests();
  }
  uint64_t p = 143669;
  uint64_t q = 29569;
  uint64_t n = p * q;
  uint64_t phiResult = phi(p, q);
  struct Key public;
  struct Key private;

  keyGeneration(&phiResult, &private, &public);

  printf("\nLogs from main:\n"
    "• p: %" PRIu64 "\n"
    "• q: %" PRIu64 "\n"
    "• n: %" PRIu64 "\n"
    "• phiResult: %" PRIu64 "\n"
    "• e: %" PRIu64 "\n"
    "• d: %" PRIu64 "\n",
    p, q, n, phiResult, public.key, private.key);

  encryptTxt(INITIAL_FILE_PATH, ENCRYPTED_FILE_PATH, &public, n);
  decryptTxt(ENCRYPTED_FILE_PATH, DECRYPTED_FILE_PATH, &private, n);
  
  printf("\nDemonstrating signature validation:\n");
  char testMessage = 'R'; 
  uint64_t messageValue = (uint64_t)testMessage;
  uint64_t signature = signMessage(messageValue, &private, n);
  int isValid = verifySignature(messageValue, signature, &public, n);
  
  printf("• Message: '%c' (value: %" PRIu64 ")\n", testMessage, messageValue);
  printf("• Digital signature: %" PRIu64 "\n", signature);
  printf("• Signature verification: %s\n", isValid ? "VALID" : "INVALID");
  
  return 0;
}
