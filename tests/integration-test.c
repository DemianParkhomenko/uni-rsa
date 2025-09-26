#include "../src/crypto.h"
#include "../src/key-gen.h"
#include "../src/types/keys.h"
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>

const char* GREEN = "\033[0;32m";
const char* RESET = "\033[0m";

void testRSA(uint64_t p, uint64_t q, char x) {
  uint64_t n = p * q;
  uint64_t phiResult = phi(p, q);

  struct Key public;
  struct Key private;

  keyGeneration(&phiResult, &private, &public);
  uint64_t modInverseResEAndD = public.key * private.key % phiResult;

  //* test keys generation
  uint64_t dummyD; //*don't reassign private key
  uint64_t gcdPhiResultAndE = eea(phiResult, public.key, &dummyD);
  uint64_t encrypted = exponentAndMod((uint64_t)x, public.key, public.binKey,
    public.binKeyNumberOfBits, n);
  char decrypted = (char)exponentAndMod(encrypted, private.key, private.binKey,
    private.binKeyNumberOfBits, n);
  //*

  printf("\n%sTest with p: %lu, q: %lu is valid.%s\n", GREEN, p, q, RESET);
  printf("• p: %" PRIu64 "\n"
    "• q: %" PRIu64 "\n"
    "• n: %" PRIu64 "\n"
    "• phiResult: %" PRIu64 "\n"
    "• e: %" PRIu64 "\n"
    "• d: %" PRIu64 "\n"
    "• gcd(phiResult,e) = %" PRIu64 "\n"
    "• e * d mod phi(n) = %" PRIu64 "\n"
    "• initial text: %c\n"
    "• encrypted text: %" PRIu64 "\n"
    "• decrypted text: %c\n",
    p, q, n, phiResult, public.key, private.key, gcdPhiResultAndE,
    modInverseResEAndD, x, encrypted, decrypted);
  assert(public.key < n);
  assert(x == decrypted);
  assert(1 == gcdPhiResultAndE);
  assert(1 == modInverseResEAndD);
}

void testSignature(uint64_t p, uint64_t q, char message) {
  uint64_t n = p * q;
  uint64_t phiResult = phi(p, q);

  struct Key public;
  struct Key private;

  keyGeneration(&phiResult, &private, &public);
  
  uint64_t messageValue = (uint64_t)message;
  uint64_t signature = signMessage(messageValue, &private, n);
  int isValid = verifySignature(messageValue, signature, &public, n);

  printf("\n%sSignature test with p: %lu, q: %lu is valid.%s\n", GREEN, p, q, RESET);
  printf("• message: '%c' (value: %" PRIu64 ")\n"
    "• signature: %" PRIu64 "\n"
    "• verification result: %s\n",
    message, messageValue, signature, isValid ? "VALID" : "INVALID");
    
  assert(isValid == 1);
}

void integrationTests() {
  printf("\nRunning tests...\n");
  testRSA(26497, 78577, 'U');
  testRSA(45433, 92377, 'K');
  testRSA(159979, 28051, 'R');
  testRSA(100129, 25033, 'A');
  testRSA(16871, 56519, 'I');
  testRSA(69031, 6359, 'N');
  testRSA(14771, 113083, 'E');

  printf("\nTest with small numbers\nInital text is null character\n");
  testRSA(3, 11, '\0'); /*the binary value of the plaintext x must be less
          than n so use null character which has 0 binary representation in
          ASCII table for small p and q (p*q = n)*/

  printf("\nRunning signature validation tests...\n");
  testSignature(26497, 78577, 'U');
  testSignature(45433, 92377, 'K');
  testSignature(159979, 28051, 'R');
  testSignature(100129, 25033, 'A');
  testSignature(16871, 56519, 'I');
  testSignature(69031, 6359, 'N');
  testSignature(14771, 113083, 'E');
  
  printf("\nTesting signature with small numbers\n");
  testSignature(3, 11, '\0');
}
