#include "payload_obfuscation.h"

#include <stdlib.h>
#include <string.h>

unsigned char *xor_payload(const unsigned char *payload, size_t payload_len,
                           const char *agent_id) {
    size_t key_len;
    unsigned char *transformed;
    size_t i;

    if ((!payload && payload_len > 0) || !agent_id || agent_id[0] == '\0')
        return NULL;

    if (payload_len == 0)
        return (unsigned char *)malloc(1);

    key_len = strlen(agent_id);
    transformed = (unsigned char *)malloc(payload_len);
    if (!transformed)
        return NULL;

    for (i = 0; i < payload_len; i++)
        transformed[i] = payload[i] ^ (unsigned char)agent_id[i % key_len];
    return transformed;
}
