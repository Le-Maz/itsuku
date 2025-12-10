// W pliku challenge_id.h
#ifndef CHALLENGE_ID_H
#define CHALLENGE_ID_H

#include <stddef.h>
#include <stdint.h>

typedef struct ChallengeId {
  uint8_t *bytes;
  size_t bytes_len;
} ChallengeId;

// Deklaracje funkcji dla ChallengeId (BRAKUJĄCE)
ChallengeId *ChallengeId__new(const uint8_t *bytes, size_t bytes_len);
void ChallengeId__drop(ChallengeId *self);

#endif // CHALLENGE_ID_H
