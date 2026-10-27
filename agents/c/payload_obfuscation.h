/*
 * Symmetric XOR payload transformation.
 */
#ifndef PAYLOAD_OBFUSCATION_H
#define PAYLOAD_OBFUSCATION_H

#include <stddef.h>

/*
 * Allocates a transformed copy of payload. XOR is its own inverse, so this
 * function is used for both encryption and decryption.
 * Returns NULL for invalid input or allocation failure.
 */
unsigned char *xor_payload(const unsigned char *payload, size_t payload_len,
                           const char *agent_id);

#endif
