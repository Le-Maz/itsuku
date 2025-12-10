#ifndef CHALLENGE_ID_H
#define CHALLENGE_ID_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Represents an identifier composed of an owned byte buffer.
 *
 * The structure stores a pointer to dynamically allocated bytes and
 * the associated length of that buffer.
 */
typedef struct ChallengeId {
  uint8_t *bytes;   // Pointer to the allocated byte array
  size_t bytes_len; // Number of bytes stored
} ChallengeId;

/**
 * @brief Allocates and initializes a new ChallengeId instance.
 *
 * The function copies the provided bytes into an owned buffer and
 * returns a pointer to a dynamically allocated structure. Ownership
 * is transferred to the caller, who is responsible for freeing it.
 */
ChallengeId *ChallengeId__new(const uint8_t *input_bytes,
                              size_t input_bytes_length);

/**
 * @brief Releases all memory associated with a ChallengeId instance.
 *
 * Frees both the internal byte buffer and the structure itself.
 * Safe to call with NULL.
 */
void ChallengeId__drop(ChallengeId *self);

#endif // CHALLENGE_ID_H
