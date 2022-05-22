#include "../src/crypto.h"
#include "../src/key-gen.h"
#include <assert.h>
#include <stdint.h>

const char *GREEN = "\033[0;32m";
const char *RESET = "\033[0m";

void makeTest(uint64_t p, uint64_t q, char x) {
  uint64_t n = p * q;
  uint64_t phiResult = phi(p, q);
  uint64_t e;
  uint64_t d;
  char binEArr[64];
  short binENumberOfBits;
  char binDArr[64];
  short binDNumberOfBits;
  keyGeneration(&phiResult, &e, &d, binEArr, &binENumberOfBits, binDArr,
                &binDNumberOfBits);

  uint64_t dummyD; //*don't reassign private key
  uint64_t gcdPhiResultAndE = eea(phiResult, e, &dummyD);
  uint64_t modInverseResEAndD = e * d % phiResult;
  uint64_t encrypted =
      exponentAndMod((uint64_t)x, e, binEArr, binENumberOfBits, n);
  char decrypted =
      (char)exponentAndMod(encrypted, d, binDArr, binDNumberOfBits, n);

  printf("\n%sTest with p: %d, q: %d is valid.%s\n", GREEN, p, q, RESET);
  printf("• p = %d\n"
         "• q = %d\n"
         "• n = %d\n"
         "• phiResult = %d\n"
         "• e = %d\n"
         "• gcd(phi(n),e) = %d\n"
         "• d = %d\n"
         "• e * d mod phi(n) = %d\n",
         p, q, n, phiResult, e, gcdPhiResultAndE, d, modInverseResEAndD);
  assert(e < n);
  assert(x == decrypted);
  assert(1 == gcdPhiResultAndE);
  assert(1 == modInverseResEAndD);
}

void integrationTests() {
  printf("\nRunning tests...\n");
  makeTest(2311, 78577, 'U');
  makeTest(45433, 92377, 'K');
  makeTest(159979, 1471, 'R');
  makeTest(100129, 25033, 'A');
  makeTest(7159, 56519, 'I');
  makeTest(69031, 6359, 'N');
  makeTest(14771, 113083, 'E');
  
  printf("\nTest with small numbers\n");
  makeTest(3, 11,
           '\0'); //*  the binary value of the plaintext x must be less than n
  //* so use null character which has 0 binary representation in ASCII table for
  //* small p and q (p*q = n)
}