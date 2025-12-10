#include "challenge_id.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Allocates and initializes a new ChallengeId structure.
 *
 * Takes ownership of the copied bytes.
 */
ChallengeId *ChallengeId__new(const uint8_t *input_bytes,
                              size_t input_bytes_length) {
  ChallengeId *challenge_id = (ChallengeId *)malloc(sizeof(ChallengeId));
  if (!challenge_id) {
    return NULL; // Failed to allocate structure
  }

  challenge_id->bytes = (uint8_t *)malloc(input_bytes_length);
  if (!challenge_id->bytes) {
    free(challenge_id);
    return NULL; // Failed to allocate internal byte buffer
  }

  memcpy(challenge_id->bytes, input_bytes, input_bytes_length);
  challenge_id->bytes_len = input_bytes_length;

  return challenge_id;
}

/**
 * @brief Deallocates a ChallengeId structure, including its stored bytes.
 */
void ChallengeId__drop(ChallengeId *self) {
  if (self) {
    free(self->bytes); // Free internal byte buffer
    free(self);        // Free structure itself
  }
}
