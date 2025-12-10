#include "challenge_id.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Alokuje i inicjalizuje nową strukturę ChallengeId.
 *
 * Przejmuje własność nad skopiowanymi bajtami.
 */
ChallengeId *ChallengeId__new(const uint8_t *bytes, size_t bytes_len) {
  ChallengeId *id = (ChallengeId *)malloc(sizeof(ChallengeId));
  if (!id) {
    return NULL;
  }

  id->bytes = (uint8_t *)malloc(bytes_len);
  if (!id->bytes) {
    free(id);
    return NULL;
  }

  memcpy(id->bytes, bytes, bytes_len);
  id->bytes_len = bytes_len;

  return id;
}

/**
 * @brief Dealokuje strukturę ChallengeId, w tym przechowywane bajty.
 */
void ChallengeId__drop(ChallengeId *self) {
  if (self) {
    free(self->bytes);
    free(self);
  }
}
