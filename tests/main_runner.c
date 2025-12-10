#include "../src/memory.h"
#include "itsuku_tests.h"
#include <stdio.h>
#include <stdlib.h>

// --- Deklaracje funkcji pomocniczych (potrzebne do linkowania) ---
extern void u64_to_le_bytes(uint64_t x, uint8_t out[8]);
extern Element Element__zero();

// =================================================================
// FUNKCJE POMOCNICZE
// =================================================================

int total_errors = 0; // Definicja globalnego licznika

ChallengeId *build_test_challenge_id() {
  uint8_t bytes[64];
  for (int i = 0; i < 64; ++i) {
    bytes[i] = (uint8_t)i;
  }
  return ChallengeId__new(bytes, 64);
}

// =================================================================
// FUNKCJA GŁÓWNA TESTÓW
// =================================================================

int main() {
  printf("--- Uruchamianie testów Itsuku ---\n\n");

  // GRUPA 1: KONFIGURACJA, ALOKACJA, INDEKSOWANIE
  printf("--- GRUPA 1/2: Core i Indeksowanie ---\n");
  test_config_defaults();
  test_challenge_id_allocation();
  test_memory_allocation();
  test_indexing_argon2();
  test_indexing_phi_variants();
  test_element_operations();
  printf("--- Zakończono testy Core i Indeksowania ---\n");

  // GRUPA 3: FUNKCJONALNE PAMIĘCI
  printf("\n--- GRUPA 3: Funkcjonalność Pamięci ---\n");
  test_memory_build_chunk_determinism();
  test_trace_element_reproducibility();
  test_memory_build_chunk_determinism_rust_ref();
  printf("--- Zakończono testy Pamięci ---\n");

  // GRUPA 4: MERKLE TREE
  printf("\n--- GRUPA 4: Merkle Tree ---\n");
  test_merkle_node_size();
  test_merkle_tree_allocation();
  test_merkle_root_matches_rust();
  test_merkle_trace_node();
  printf("--- Zakończono testy Merkle Tree ---\n");

  // GRUPA 5: PROOF-OF-WORK
  printf("\n--- GRUPA 5: Proof-of-Work ---\n");
  test_proof_leading_zeros();
  test_proof_search_and_verify_success();
  printf("--- Zakończono testy Proof-of-Work ---\n");

  // Podsumowanie
  if (total_errors > 0) {
    fprintf(stderr, "\n\n!!! WYNIK: Niepowodzenie (%d błędów) !!!\n",
            total_errors);
    return EXIT_FAILURE;
  } else {
    printf("\n\n--- WYNIK: Sukces (wszystkie testy pomyślne) ---\n");
    return EXIT_SUCCESS;
  }
}
