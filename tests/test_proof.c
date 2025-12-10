#include "../src/config.h"
#include "../src/hashmap.h"
#include "../src/memory.h"
#include "../src/merkle_tree.h"
#include "../src/proof.h"
#include "itsuku_tests.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --- Auxiliary Function Declaration (from itsuku_tests.c/main_runner.c) ---
extern ChallengeId *build_test_challenge_id();
extern MerkleTree *MerkleTree__build_for_test(Config config,
                                              ChallengeId *challenge_id,
                                              Memory *memory);

// Golden Standard for Proof tests
const size_t PROOF_TEST_CHUNK_COUNT = 16;
const size_t PROOF_TEST_CHUNK_SIZE = 64;
const size_t PROOF_TEST_DIFFICULTY = 8;
const size_t PROOF_TEST_MEMORY_SIZE =
    PROOF_TEST_CHUNK_COUNT * PROOF_TEST_CHUNK_SIZE; // 1024

// =================================================================
// GROUP 5: PROOF-OF-WORK FUNCTIONALITY
// =================================================================

void test_proof_leading_zeros() {
  const char *name = "Proof Leading Zeros Count";
  printf("  [Test] %s\n", name);

  // 0. Zero
  uint8_t a[] = {0x00, 0x00, 0x00, 0x00};
  TEST_ASSERT(Proof__leading_zeros(a, 4) == 32, name);

  // 1. Two full zero bytes, third byte 0x80 (10000000)
  uint8_t b[] = {0x00, 0x00, 0x80, 0x00};
  TEST_ASSERT(Proof__leading_zeros(b, 4) == 16, name);

  // 2. One full zero byte, second byte 0x01 (00000001) -> 8 + 7 = 15 zeros
  uint8_t c[] = {0x00, 0x01, 0x00, 0x00};
  TEST_ASSERT(Proof__leading_zeros(c, 4) == 15, name);

  // 3. No zero bytes, first byte 0x10 (00010000) -> 3 zeros
  uint8_t d[] = {0x10, 0x00, 0x00, 0x00};
  TEST_ASSERT(Proof__leading_zeros(d, 4) == 3, name);
}

/**
 * @brief Simulates the full PoW cycle: memory build, tree build, and search.
 * Returns a correctly verified Proof.
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

  // Build the tree
  MerkleTree__compute_leaf_hashes(merkle_tree, challenge_id, memory);
  MerkleTree__compute_intermediate_nodes(merkle_tree, challenge_id);

  // Search for the Proof.
  Proof *proof = Proof__search(config, challenge_id, memory, merkle_tree);

  // Check verification
  if (proof) {
    VerificationError err = Proof__verify(proof);
    if (err != VerificationError__Ok) {
      // Verification failed
      fprintf(stderr,
              "!!! ERROR: Proof verification failed with error code: %d\n",
              err);
      Proof__drop(proof);
      proof = NULL;
    }
  }

  // Free memory and Merkle tree resources
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
    // Check basic data
    TEST_ASSERT(proof->config.difficulty_bits == PROOF_TEST_DIFFICULTY, name);
    TEST_ASSERT(proof->nonce != 0, name);

    // Structural validation to ensure the Proof was correctly built
    TEST_ASSERT(HashMap__size(proof->leaf_antecedents) ==
                    proof->config.search_length,
                "Antecedent count mismatch");
    // Number of nodes in the tree opening should be close to L * 2
    TEST_ASSERT(HashMap__size(proof->tree_opening) >
                    proof->config.search_length,
                "Tree opening size is too small");

    Proof__drop(proof);
  }
}
