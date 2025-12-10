#ifndef ITSUKU_TESTS_H
#define ITSUKU_TESTS_H

#include "../src/challenge_id.h"
#include <limits.h>

// Global error counter
extern int total_errors;

/**
 * @brief Macro to check a condition and count errors without interrupting.
 */
#define TEST_ASSERT(condition, test_name)                                      \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "!!! ERROR: %s. Condition: %s. File: %s, Line: %d\n",    \
              test_name, #condition, __FILE__, __LINE__);                      \
      total_errors++;                                                          \
    }                                                                          \
  } while (0)

// Helper function to build a ChallengeId for tests
ChallengeId *build_test_challenge_id();

// --- TEST GROUP DECLARATIONS ---

// GROUP 1/2/3 (Core)
void test_config_defaults();
void test_challenge_id_allocation();
void test_memory_allocation();
void test_indexing_argon2();
void test_indexing_phi_variants();
void test_element_operations();

// GROUP 3 (Memory)
void test_memory_build_chunk_determinism();
void test_trace_element_reproducibility();
void test_memory_build_chunk_determinism_rust_ref();

// GROUP 4 (Merkle Tree)
void test_merkle_node_size();
void test_merkle_tree_allocation();
void test_merkle_root_matches_rust();
void test_merkle_trace_node();

// GROUP 5 (Proof)
void test_proof_leading_zeros();
void test_proof_search_and_verify_success();

#endif // ITSUKU_TESTS_H
