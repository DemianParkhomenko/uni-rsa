#include <stdint.h>

//* tests key generation and encrypting/decrypting with different primes numbers
void integrationTests(void);

//* tests signature creation and verification with different primes numbers
void testSignature(uint64_t p, uint64_t q, char message);
