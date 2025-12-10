#include "itsuku_tests.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// =================================================================
// AUXILIARY FUNCTIONS
// =================================================================

int total_errors = 0; // Definition of the global counter

ChallengeId *build_test_challenge_id() {
  uint8_t bytes[64];
  for (int i = 0; i < 64; ++i) {
    bytes[i] = (uint8_t)i;
  }
  return ChallengeId__new(bytes, 64);
}

// =================================================================
// MAIN TEST FUNCTION
// =================================================================

int main() {
  printf("--- Running Itsuku Tests ---\n\n");

  // GROUP 1/2: CORE, CONFIGURATION, ALLOCATION, INDEXING
  printf("--- GROUP 1/2: Core and Indexing Tests ---\n");
  test_config_defaults();
  test_challenge_id_allocation();
  test_memory_allocation();
  test_indexing_argon2();
  test_indexing_phi_variants();
  test_element_operations();
  printf("--- Core and Indexing Tests Completed ---\n");

  // GROUP 3: MEMORY FUNCTIONAL TESTS
  printf("\n--- GROUP 3: Memory Functionality Tests ---\n");
  test_memory_build_chunk_determinism();
  test_trace_element_reproducibility();
  test_memory_build_chunk_determinism_rust_ref();
  printf("--- Memory Tests Completed ---\n");

  // GROUP 4: MERKLE TREE
  printf("\n--- GROUP 4: Merkle Tree Tests ---\n");
  test_merkle_node_size();
  test_merkle_tree_allocation();
  test_merkle_root_matches_rust();
  test_merkle_trace_node();
  printf("--- Merkle Tree Tests Completed ---\n");

  // GROUP 5: PROOF-OF-WORK
  printf("\n--- GROUP 5: Proof-of-Work Tests ---\n");
  test_proof_leading_zeros();
  test_proof_search_and_verify_success();
  printf("--- Proof-of-Work Tests Completed ---\n");

  // Summary
  if (total_errors > 0) {
    fprintf(stderr, "\n\n!!! RESULT: Failure (%d errors) !!!\n", total_errors);
    return EXIT_FAILURE;
  } else {
    printf("\n\n--- RESULT: Success (all tests passed) ---\n");
    return EXIT_SUCCESS;
  }
}
