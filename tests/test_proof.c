#include "../src/config.h"
#include "../src/hashmap.h"
#include "../src/memory.h"
#include "../src/merkle_tree.h"
#include "../src/proof.h"
#include "itsuku_tests.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Złoty Wzorzec dla testów Proof
const size_t PROOF_TEST_CHUNK_COUNT = 16;
const size_t PROOF_TEST_CHUNK_SIZE = 64;
const size_t PROOF_TEST_DIFFICULTY = 8;

// =================================================================
// GRUPA 5: FUNKCJONALNOŚĆ PROOF-OF-WORK
// =================================================================

void test_proof_leading_zeros() {
  const char *name = "Proof Leading Zeros Count";
  printf("  [Test] %s\n", name);

  // 0. Zero
  uint8_t a[] = {0x00, 0x00, 0x00, 0x00};
  TEST_ASSERT(Proof__leading_zeros(a, 4) == 32, name);

  // 1. Dwa całe bajty zero, trzeci bajt 0x80 (10000000)
  uint8_t b[] = {0x00, 0x00, 0x80, 0x00};
  TEST_ASSERT(Proof__leading_zeros(b, 4) == 16, name);

  // 2. Jeden cały bajt zero, drugi bajt 0x01 (00000001) -> 8 + 7 = 15 zer
  uint8_t c[] = {0x00, 0x01, 0x00, 0x00};
  TEST_ASSERT(Proof__leading_zeros(c, 4) == 15, name);

  // 3. Brak zerowych bajtów, pierwszy bajt 0x10 (00010000) -> 3 zera
  uint8_t d[] = {0x10, 0x00, 0x00, 0x00};
  TEST_ASSERT(Proof__leading_zeros(d, 4) == 3, name);
}

/**
 * @brief Symuluje pełny cykl PoW: budowanie pamięci, drzewa i poszukiwanie.
 * Zwraca poprawnie zweryfikowany Proof.
 */
Proof *Proof__solves_and_verifies() {
  Config config = Config__default();
  config.chunk_count = PROOF_TEST_CHUNK_COUNT;
  config.chunk_size = PROOF_TEST_CHUNK_SIZE;
  config.difficulty_bits = PROOF_TEST_DIFFICULTY;

  ChallengeId *challenge_id = build_test_challenge_id();
  Memory *memory = Memory__new(config);
  Memory__build_all_chunks(memory, challenge_id);
  MerkleTree *merkle_tree = MerkleTree__new(config);

  MerkleTree__compute_leaf_hashes(merkle_tree, challenge_id, memory);
  MerkleTree__compute_intermediate_nodes(merkle_tree, challenge_id);

  Proof *proof = Proof__search(config, challenge_id, memory, merkle_tree);

  if (proof) {
    VerificationError err = Proof__verify(proof);
    if (err != VerificationError__Ok) {
      fprintf(stderr,
              "!!! BLAD: Proof verification failed with error code: %d\n", err);
      Proof__drop(proof);
      proof = NULL;
    }
  }

  MerkleTree__drop(merkle_tree);
  Memory__drop(memory);
  ChallengeId__drop(challenge_id);

  return proof;
}

void test_proof_search_and_verify_success() {
  const char *name = "Proof Search and Verify Success (d=8)";
  printf("  [Test] %s\n", name);

  Proof *proof = Proof__solves_and_verifies();

  TEST_ASSERT(proof != NULL, name);
  if (proof) {
    TEST_ASSERT(proof->config.difficulty_bits == PROOF_TEST_DIFFICULTY, name);
    TEST_ASSERT(proof->nonce != 0, name);

    // Walidacja strukturalna, aby upewnić się, że Proof został poprawnie
    // zbudowany
    TEST_ASSERT(HashMap__size(proof->leaf_antecedents) ==
                    proof->config.search_length,
                "Antecedent count mismatch");
    TEST_ASSERT(HashMap__size(proof->tree_opening) >
                    proof->config.search_length,
                "Tree opening size is too small");

    Proof__drop(proof);
  }
}
