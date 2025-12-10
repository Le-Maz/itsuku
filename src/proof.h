#ifndef PROOF_H
#define PROOF_H

#include "challenge_id.h"
#include "config.h"
#include "hashmap.h"
#include "memory.h"
#include "merkle_tree.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// --- Błędy Weryfikacji (error.rs) ---

typedef enum VerificationError {
  VerificationError__Ok = 0,
  VerificationError__InvalidAntecedentCount,
  VerificationError__MissingOpeningForLeaf,
  VerificationError__LeafHashMismatch,
  VerificationError__IntermediateHashMismatch,
  VerificationError__MissingMerkleRoot,
  VerificationError__MalformedProofPath,
  VerificationError__UnprovenLeafInPath,
  VerificationError__DifficultyNotMet,
  VerificationError__RequiredElementMissing,
  VerificationError__MissingChildNode,
} VerificationError;

// --- Struktura Proof ---

/**
 * @brief A cryptographic Proof-of-Work (PoW) solution for the Itsuku scheme.
 * * Endianness field is implicitly Little Endian.
 */
typedef struct Proof {
  Config config;
  ChallengeId challenge_id;
  uint64_t nonce;

  // map from leaf index (usize) to the list of Elements (Vec<Element>)
  HashMap leaf_antecedents;

  // map from Merkle node index (usize) to its hash (Bytes)
  HashMap tree_opening;
} Proof;

// --- Funkcje dla Proof ---

/**
 * @brief Initiates a multi-threaded nonce search for a valid proof.
 * * Proof::search(config, challenge_id, memory, merkle_tree)
 * @return The first valid Proof found (dynamically allocated).
 */
Proof *Proof__search(Config config, const ChallengeId *challenge_id,
                     const Memory *memory, const MerkleTree *merkle_tree);

/**
 * @brief Deallocates the Proof structure.
 */
void Proof__drop(Proof *self);

/**
 * @brief Calculates the final Omega hash for a given nonce.
 * * Proof::calculate_omega(...)
 */
void Proof__calculate_omega(uint8_t omega_out[64],
                            size_t *selected_leaves_len_out,
                            size_t **selected_leaves_out, size_t *path_len_out,
                            uint8_t ***path_hashes_out, const Config *config,
                            const ChallengeId *challenge_id,
                            PartialMemory_Wrapper memory_wrapper,
                            PartialMerkleTree_Wrapper merkle_tree_wrapper,
                            const uint8_t root_hash[64], size_t memory_size,
                            uint64_t nonce);

/**
 * @brief Counts the number of leading zero bits in a byte array.
 */
size_t Proof__leading_zeros(const uint8_t *array, size_t size);

/**
 * @brief Verifies the PoW proof against the challenge and configuration.
 * * Proof::verify(&self)
 * @return VerificationError__Ok if valid, or a specific error otherwise.
 */
VerificationError Proof__verify(const Proof *self);

#endif // PROOF_H
