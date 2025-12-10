#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --- Dołączanie nagłówków projektu ---
#include "../src/challenge_id.h"
#include "../src/config.h"
#include "../src/itsuku.h"
#include "../src/memory.h"
#include "../src/merkle_tree.h"
#include "../src/proof.h"

// --- Deklaracje funkcji pomocniczych (potrzebne do linkowania) ---
extern void u64_to_le_bytes(uint64_t x, uint8_t out[8]);
extern Element Element__zero();

// =================================================================
// MECHANIZM TESTOWANIA Z KONTUNUACJĄ
// =================================================================

// Globalny licznik błędów
static int total_errors = 0;

/**
 * @brief Makro do sprawdzania warunku i zliczania błędów bez przerywania.
 * Zastępuje standardowe assert().
 */
#define TEST_ASSERT(condition, test_name)                                      \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "!!! BLAD: %s. Warunek: %s. Plik: %s, Linia: %d\n",      \
              test_name, #condition, __FILE__, __LINE__);                      \
      total_errors++;                                                          \
    }                                                                          \
  } while (0)

// Funkcja pomocnicza do budowania ChallengeId dla testów
ChallengeId *build_test_challenge_id() {
  uint8_t bytes[64];
  for (int i = 0; i < 64; ++i) {
    bytes[i] = (uint8_t)i;
  }
  return ChallengeId__new(bytes, 64);
}

// =================================================================
// GRUPA 1: KONFIGURACJA I ALOKACJA PAMIĘCI
// =================================================================

void test_config_defaults() {
  const char *name = "Config Defaults";
  printf("  [Test] %s\n", name);
  Config c = Config__default();

  TEST_ASSERT(c.chunk_size == 32768, name);
  TEST_ASSERT(c.chunk_count == 1024, name);
  TEST_ASSERT(c.antecedent_count == 4, name);
  TEST_ASSERT(c.difficulty_bits == 24, name);
  TEST_ASSERT(c.search_length == 9, name);
}

void test_challenge_id_allocation() {
  const char *name = "Challenge ID Allocation";
  printf("  [Test] %s\n", name);
  uint8_t raw_id[] = {0xAA, 0xBB, 0xCC};
  size_t len = 3;

  ChallengeId *id = ChallengeId__new(raw_id, len);

  TEST_ASSERT(id != NULL, name);
  if (id) {
    TEST_ASSERT(id->bytes_len == len, name);
    TEST_ASSERT(memcmp(id->bytes, raw_id, len) == 0, name);
    ChallengeId__drop(id);
  }
}

void test_merkle_node_size() {
  const char *name = "Merkle Node Size Calculation";
  printf("  [Test] %s\n", name);
  Config c = Config__default();

  // Test d=70, L=9: M=10
  c.difficulty_bits = 70;
  size_t node_size_70 = MerkleTree__calculate_node_size(&c);
  TEST_ASSERT(node_size_70 == 10, name);

  // Test d=24, L=9: M=5 (zgodnie z matematycznym wynikiem ceil)
  c.difficulty_bits = 24;
  c.search_length = 9;
  size_t node_size_24 = MerkleTree__calculate_node_size(&c);
  TEST_ASSERT(node_size_24 == 5, name);
}

void test_memory_allocation() {
  const char *name = "Memory Allocation";
  printf("  [Test] %s\n", name);
  Config c = Config__default();
  Memory *mem = Memory__new(c);

  TEST_ASSERT(mem != NULL, name);
  if (mem) {
    TEST_ASSERT(mem->chunks != NULL, name);
    TEST_ASSERT(mem->chunks[0] != NULL, name);

    // Sprawdź, czy pamięć jest zainicjalizowana zerami
    Element *first_element = Memory__get(mem, 0);
    if (first_element) {
      TEST_ASSERT(
          memcmp(first_element->data, Element__zero().data, ELEMENT_SIZE) == 0,
          name);
    }

    Memory__drop(mem);
  }
}

// =================================================================
// GRUPA 2: FUNKCJE INDEKSUJĄCE (ITSUKU)
// =================================================================

void test_indexing_argon2() {
  const char *name = "Argon2 Indexing";
  printf("  [Test] %s\n", name);

  uint8_t seed1[] = {0x01, 0x00, 0x00, 0x00};
  size_t idx1 = calculate_argon2_index(seed1, 1000);

  // Poprawiona asercja z 0 na 999 (Z = 1000 - 1 - 0 = 999)
  TEST_ASSERT(idx1 == 999, name);
}

void test_indexing_phi_variants() {
  const char *name = "Phi Variants";
  printf("  [Test] %s\n", name);
  size_t i = 1024;
  size_t argon2_idx = 100;

  // T1.4: k=0 (i-1)
  TEST_ASSERT(calculate_phi_variant_index(i, argon2_idx, 0) == 1023, name);

  // T1.5: k=2 (phi+i)/2
  TEST_ASSERT(calculate_phi_variant_index(i, argon2_idx, 2) == 562, name);

  // T1.6: k=3 (7*i)/8
  TEST_ASSERT(calculate_phi_variant_index(i, argon2_idx, 3) == 896, name);

  // T1.7: k=11 (7*i)/8
  TEST_ASSERT(calculate_phi_variant_index(i, argon2_idx, 11) == 896, name);

  // k=10: (7*phi)/8
  TEST_ASSERT(calculate_phi_variant_index(i, argon2_idx, 10) == 87, name);
}

/**
 * @brief Testuje wewnętrzne operacje (ADD i XOR) na Elementach.
 */
void test_element_operations() {
  const char *name = "Element Operations";
  printf("  [Test] %s\n", name);

  Element a = Element__zero();
  Element b = Element__zero();
  Element c = Element__zero();

  // Ustawienie wartości, które spowodują przepełnienie (wrapping) przy
  // dodawaniu
  uint64_t val_a = 0xFFFFFFFFFFFFFFF0UL; // -16
  uint64_t val_b = 0x0000000000000010UL; // +16
  uint64_t val_x = 0xAAAAAAAAAAAAAAAALL;
  uint64_t val_y = 0x5555555555555555LL;

  // Inicjalizacja A i B
  a.data[0] = val_a;
  a.data[1] = val_x;
  b.data[0] = val_b;
  b.data[1] = val_y;

  // 1. Test ADD (Wrapping)
  c = a;                       // c = A
  Element__add_assign(&c, &b); // c = A + B

  // Oczekiwane dla c.data[0]: 0xFF..F0 + 0x10 = 0 (przepełnienie)
  TEST_ASSERT(c.data[0] == 0UL, name);

  // Oczekiwane dla c.data[1]: 0xAAAA... + 0x5555... = 0xFFFF...
  // TUTAJ JEST BŁĄD LOGICZNY W ORYGINALNYM TEŚCIE - POWINNO BYĆ ULLONG_MAX
  TEST_ASSERT(c.data[1] == ULLONG_MAX, name);

  // 2. Test XOR
  c = a;                          // c = A
  Element__bitxor_assign(&c, &b); // c = A ^ B
  // Oczekiwane: c.data[1] = 0xAAAA ^ 0x5555 = 0xFF..FF
  TEST_ASSERT(c.data[1] == ULLONG_MAX, name);
}

/**
 * @brief Testuje, czy Memory__build_chunk poprawnie inicjalizuje
 * i używa funkcji kompresji dla iteracyjnej budowy.
 * * UWAGA: Ten test nie weryfikuje poprawności hashy, tylko determinizm i
 * wykonanie.
 */
void test_memory_build_chunk_determinism() {
  const char *name = "Build Chunk Determinism";
  printf("  [Test] %s\n", name);

  Config c = Config__default(); // L=9, n=4, T=32768
  c.antecedent_count = 4;
  c.chunk_size = 8; // Mały chunk dla prostego testu

  uint8_t raw_id[] = {0x01, 0x02, 0x03, 0x04};
  ChallengeId id = {.bytes = raw_id, .bytes_len = 4};

  Memory *mem1 = Memory__new(c);
  Memory *mem2 = Memory__new(c);

  // Dwa niezależne wykonania na identycznych danych
  Memory__build_chunk(&c, 0, mem1->chunks[0], &id);
  Memory__build_chunk(&c, 0, mem2->chunks[0], &id);

  // Weryfikacja: Hash pierwszego (i=0, inicjalizacja)
  Element *e1_init = Memory__get(mem1, 0);
  Element *e2_init = Memory__get(mem2, 0);

  TEST_ASSERT(memcmp(e1_init->data, e2_init->data, ELEMENT_SIZE) == 0, name);

  // Weryfikacja: Hash ostatniego elementu (i=7, kompresja)
  Element *e1_comp = Memory__get(mem1, 7);
  Element *e2_comp = Memory__get(mem2, 7);

  // Kluczowa asercja: Zależność danych musi prowadzić do identycznego wyniku
  TEST_ASSERT(memcmp(e1_comp->data, e2_comp->data, ELEMENT_SIZE) == 0, name);

  Memory__drop(mem1);
  Memory__drop(mem2);
}

/**
 * @brief Weryfikacja kluczowych indeksów i reprodoukowalności budowania
 */
void test_trace_element_reproducibility() {
  const char *name = "Trace Element Reproducibility";
  printf("  [Test] %s\n", name);

  Config config = Config__default();
  config.chunk_count = 2;
  config.chunk_size = 8;
  config.antecedent_count = 4;

  ChallengeId *challenge_id = build_test_challenge_id();

  Memory *memory = Memory__new(config);
  Memory__build_all_chunks(memory, challenge_id);

  const int total_elements = config.chunk_count * config.chunk_size;
  const int antecedent_count = config.antecedent_count;
  const int chunk_size = config.chunk_size;

  for (int global_index = 0; global_index < total_elements; global_index++) {
    Element *antecedents = NULL;
    size_t traced_count =
        Memory__trace_element(memory, global_index, &antecedents);

    const int element_index_in_chunk = global_index % chunk_size;

    if (element_index_in_chunk < antecedent_count) {
      // Faza inicjalizacji: element jest zwracany jako jedyny antecedent.
      TEST_ASSERT(traced_count == 1, name);
      TEST_ASSERT(memcmp(antecedents->data,
                         Memory__get(memory, global_index)->data,
                         ELEMENT_SIZE) == 0,
                  name);
    } else {
      // Faza kompresji: muszą być antecedent_count
      TEST_ASSERT(traced_count == (size_t)antecedent_count, name);

      // Re-kompresja i porównanie
      Element recomputed_element = Memory__compress(
          antecedents, traced_count, (uint64_t)global_index, challenge_id);
      Element *original_element = Memory__get(memory, global_index);

      TEST_ASSERT(memcmp(original_element->data, recomputed_element.data,
                         ELEMENT_SIZE) == 0,
                  name);
    }

    if (antecedents)
      free(antecedents);
  }

  Memory__drop(memory);
  ChallengeId__drop(challenge_id);
}

/**
 * @brief Porównanie wyjścia Memory__build_all_chunks z referencyjnym hashem z
 * Rust (compare_with_c_reference_output)
 */
void test_memory_build_chunk_determinism_rust_ref() {
  const char *name = "Build Determinism (Rust Ref)";
  printf("  [Test] %s\n", name);

  Config config = Config__default();
  config.chunk_count = 2;
  config.chunk_size = 8;
  config.antecedent_count = 4;

  ChallengeId *challenge_id = build_test_challenge_id();
  Memory *memory = Memory__new(config);
  Memory__build_all_chunks(memory, challenge_id);

  // ---- Expected output from Rust reference (Złoty Wzorzec) ----
  // To jest hash dla pierwszych 8 elementów pamięci (chunk 0) wygenerowany
  // przez Rust.
  const unsigned char EXPECTED_BYTES[8][64] = {
      {0x3b, 0x1d, 0xa8, 0x20, 0x03, 0xc6, 0xc8, 0x74, 0x9e, 0xd0, 0x80,
       0xb4, 0xad, 0x02, 0x04, 0x36, 0x38, 0xf1, 0x58, 0xca, 0x52, 0xe8,
       0xf1, 0x9b, 0x15, 0xbe, 0xbf, 0xd1, 0x5e, 0xcb, 0x92, 0xb4, 0x36,
       0xfc, 0xb9, 0xce, 0xef, 0x09, 0x2b, 0x5f, 0x6f, 0x8b, 0x72, 0x2f,
       0xec, 0xec, 0x6f, 0xe0, 0xed, 0x5f, 0x7b, 0xeb, 0x3a, 0xb8, 0x55,
       0xb4, 0x2e, 0xdb, 0xd3, 0x06, 0xdd, 0xc7, 0xb2, 0x97},
      {0xcb, 0x87, 0xb2, 0xa8, 0x62, 0x8b, 0x61, 0xbf, 0x35, 0xcb, 0x4b,
       0x67, 0xfa, 0xa7, 0xd0, 0x3b, 0xc0, 0x27, 0x2e, 0x2c, 0x32, 0x10,
       0xb5, 0x84, 0x01, 0x4e, 0xe2, 0x3e, 0xe2, 0xc4, 0x8d, 0x92, 0x09,
       0xbf, 0x7e, 0xc5, 0x38, 0x3a, 0xe9, 0xed, 0x41, 0x9d, 0xab, 0x2e,
       0x83, 0x17, 0xcf, 0xc9, 0x66, 0xb4, 0x6f, 0x49, 0x28, 0x8d, 0x4f,
       0x47, 0x0d, 0xdf, 0x64, 0x95, 0x5c, 0x4a, 0x13, 0x89},
      {0x7f, 0x3c, 0x79, 0x02, 0x19, 0x7e, 0xda, 0x4b, 0xf7, 0x68, 0x2c,
       0xc2, 0xc3, 0xc7, 0xa2, 0xb3, 0xef, 0x37, 0x93, 0x6f, 0xd4, 0xee,
       0x8a, 0x6d, 0x36, 0xc0, 0x89, 0x59, 0x2c, 0x76, 0x47, 0x03, 0xd2,
       0x3b, 0x62, 0x61, 0x9f, 0x15, 0x34, 0x49, 0xfb, 0xc5, 0xf2, 0xca,
       0x84, 0xee, 0xc3, 0x8c, 0xee, 0x6e, 0xbf, 0x78, 0x6f, 0xcb, 0xfc,
       0xcb, 0x3d, 0xb2, 0x2a, 0xdb, 0x52, 0x54, 0xd5, 0xed},
      {0x01, 0x32, 0xee, 0x42, 0x40, 0xbc, 0x64, 0x73, 0x35, 0x17, 0x79,
       0x0a, 0x44, 0x06, 0xed, 0x1b, 0x4a, 0x42, 0x69, 0x8f, 0x40, 0x13,
       0x3a, 0xe2, 0xf9, 0xf6, 0x5e, 0x4d, 0xac, 0x06, 0x60, 0x5f, 0x81,
       0xde, 0x40, 0x08, 0x43, 0xb7, 0x44, 0x98, 0xd3, 0x05, 0x2a, 0xf5,
       0x86, 0x49, 0xf6, 0xea, 0xaa, 0x12, 0xa4, 0x43, 0x95, 0x4d, 0x0a,
       0xef, 0xdd, 0xef, 0x52, 0xc4, 0x76, 0x4d, 0x53, 0xc7},
      {0x87, 0x0d, 0x93, 0x1c, 0x87, 0x11, 0x73, 0x13, 0x81, 0x63, 0xf5,
       0x41, 0x34, 0xc1, 0x50, 0x87, 0x66, 0x79, 0xe6, 0x3a, 0x0c, 0x43,
       0x40, 0x75, 0xd3, 0xf4, 0x74, 0xb6, 0x69, 0x79, 0x9a, 0x8b, 0x95,
       0x24, 0x26, 0x86, 0x25, 0x31, 0xb5, 0x89, 0x20, 0x63, 0x71, 0x8b,
       0x7b, 0x04, 0x45, 0xbb, 0x9e, 0xe6, 0x71, 0xd4, 0x5d, 0xf6, 0x57,
       0x2e, 0x02, 0x41, 0x07, 0x07, 0xe2, 0x67, 0x5f, 0x41},
      {0x97, 0xe2, 0xa1, 0xaf, 0x68, 0xab, 0xf9, 0x65, 0x8a, 0x6b, 0x73,
       0x1d, 0xa7, 0x81, 0x5f, 0x32, 0x0c, 0xd3, 0x63, 0x83, 0x5f, 0xbb,
       0xaa, 0xb8, 0x71, 0x29, 0xe3, 0xc6, 0x99, 0x69, 0x2d, 0x71, 0xdd,
       0xe4, 0x14, 0x65, 0x71, 0xfe, 0x34, 0x0e, 0xe9, 0x78, 0xe9, 0xbf,
       0xfd, 0x12, 0x11, 0x9c, 0xea, 0x84, 0x7e, 0xd5, 0x99, 0x9c, 0xa3,
       0x32, 0xd2, 0xab, 0x43, 0xcd, 0x97, 0x1d, 0x96, 0x3d},
      {0x2b, 0x6d, 0x8d, 0x0a, 0xfc, 0xab, 0x11, 0x11, 0x5d, 0x7e, 0xc8,
       0x2b, 0x02, 0x0b, 0x7f, 0xac, 0x84, 0x21, 0x86, 0x2b, 0x64, 0x12,
       0x02, 0x0a, 0xa6, 0x73, 0x61, 0xf2, 0x5c, 0xd3, 0x05, 0xcf, 0x5e,
       0x36, 0x10, 0x12, 0x9d, 0x0a, 0xc6, 0xab, 0x7d, 0x5c, 0xda, 0x51,
       0x9b, 0xc2, 0xee, 0xe8, 0x0d, 0xd4, 0x8d, 0x14, 0x4b, 0xb5, 0x9f,
       0x91, 0xca, 0xe8, 0xb1, 0x89, 0xc9, 0x88, 0x28, 0xd0},
      {0x6e, 0x3f, 0x76, 0x33, 0xfe, 0x74, 0x12, 0x0b, 0xcb, 0xea, 0x86,
       0xe3, 0x4d, 0xfa, 0x49, 0xd6, 0xa9, 0x39, 0xd0, 0x6f, 0x29, 0x94,
       0x51, 0x75, 0x01, 0x5e, 0x4b, 0x31, 0x2e, 0xc4, 0x1e, 0x47, 0xd2,
       0xb1, 0x2a, 0x9c, 0xf0, 0x0c, 0xe5, 0xf8, 0x0d, 0xa9, 0x4d, 0x02,
       0x9c, 0x42, 0xf7, 0x94, 0x26, 0x72, 0x30, 0x71, 0xb4, 0x9a, 0x56,
       0x83, 0x38, 0x96, 0x4d, 0x42, 0xe3, 0xaf, 0xf5, 0x78},
  };

  for (int i = 0; i < 8; ++i) {
    Element *c_el = Memory__get(memory, i);
    uint8_t c_bytes[ELEMENT_SIZE];
    Element__to_le_bytes(c_el, c_bytes);

    TEST_ASSERT(memcmp(c_bytes, EXPECTED_BYTES[i], ELEMENT_SIZE) == 0, name);
    if (memcmp(c_bytes, EXPECTED_BYTES[i], ELEMENT_SIZE) != 0) {
      fprintf(stderr,
              "   >>> Mismatch at index %d (C/Rust data is inconsistent).\n",
              i);
    }
  }

  Memory__drop(memory);
  ChallengeId__drop(challenge_id);
}

// Złoty Wzorzec z testu Rust dla Config: chunk_count=2, chunk_size=8, L=9, d=24
const uint8_t EXPECTED_ROOT_HASH[] = {0x68, 0x19, 0x65, 0xc4, 0xab};
const size_t EXPECTED_ROOT_HASH_LEN = 5; // Sprawdzamy tylko pierwsze 5 bajtów

// Funkcja pomocnicza dla testów Merkle Tree
MerkleTree *MerkleTree__build_for_test(Config config, ChallengeId *challenge_id,
                                       Memory *memory) {
  MerkleTree *tree = MerkleTree__new(config);
  if (!tree)
    return NULL;

  // 1. Obliczanie hashy liści
  MerkleTree__compute_leaf_hashes(tree, challenge_id, memory);
  // 2. Obliczanie węzłów pośrednich i korzenia
  MerkleTree__compute_intermediate_nodes(tree, challenge_id);

  return tree;
}

// =================================================================
// GRUPA 4: FUNKCJONALNOŚĆ MERKLE TREE
// =================================================================

void test_merkle_tree_allocation() {
  const char *name = "Merkle Tree Allocation and Drop";
  printf("  [Test] %s\n", name);
  Config config = Config__default();
  config.chunk_count = 2;
  config.chunk_size = 8; // Łącznie 16 elementów
  size_t total_elements = config.chunk_count * config.chunk_size; // 16

  MerkleTree *tree = MerkleTree__new(config);

  TEST_ASSERT(tree != NULL, name);
  if (tree) {
    size_t expected_node_size = MerkleTree__calculate_node_size(&config);
    size_t expected_nodes_count = 2 * total_elements - 1; // 31
    size_t expected_total_bytes = expected_nodes_count * expected_node_size;

    TEST_ASSERT(tree->node_size == expected_node_size, name); // M=5
    TEST_ASSERT(tree->nodes_len == expected_total_bytes, name);

    MerkleTree__drop(tree);
  }
}

void test_merkle_root_matches_rust() {
  const char *name = "Merkle Root Matches Rust Reference";
  printf("  [Test] %s\n", name);

  Config config = Config__default();
  config.chunk_count = 2;
  config.chunk_size = 8;
  config.antecedent_count = 4;

  ChallengeId *challenge_id = build_test_challenge_id();
  Memory *memory = Memory__new(config);
  Memory__build_all_chunks(memory, challenge_id);

  // Budowanie drzewa
  MerkleTree *tree = MerkleTree__build_for_test(config, challenge_id, memory);

  if (tree) {
    const uint8_t *root_hash = MerkleTree__get_node(tree, 0);

    TEST_ASSERT(root_hash != NULL, name);
    if (root_hash) {
      // Porównanie pierwszych 5 bajtów z EXPECTED_ROOT_HASH
      TEST_ASSERT(
          memcmp(root_hash, EXPECTED_ROOT_HASH, EXPECTED_ROOT_HASH_LEN) == 0,
          name);
    }
    MerkleTree__drop(tree);
  } else {
    TEST_ASSERT(0, "MerkleTree__new failed");
  }

  Memory__drop(memory);
  ChallengeId__drop(challenge_id);
}

void test_merkle_trace_node() {
  const char *name = "Merkle Trace Node (Authentication Path)";
  printf("  [Test] %s\n", name);

  Config config = Config__default();
  config.chunk_count = 2;
  config.chunk_size = 8;

  ChallengeId *challenge_id = build_test_challenge_id();
  Memory *memory = Memory__new(config);
  Memory__build_all_chunks(memory, challenge_id);
  MerkleTree *tree = MerkleTree__build_for_test(config, challenge_id, memory);

  if (!tree) {
    TEST_ASSERT(0, "MerkleTree__new failed");
    Memory__drop(memory);
    ChallengeId__drop(challenge_id);
    return;
  }

  // Element 15 to węzeł 15 + (16 - 1) = 30.
  size_t element_index = 15;
  size_t leaf_node_index =
      (config.chunk_count * config.chunk_size) - 1 + element_index; // 30

  // Użycie nowego interfejsu: HashMap z destruktorem 'free' dla wartości
  // (hashy)
  HashMap traced_nodes = HashMap__new(free);
  MerkleTree__trace_node(tree, leaf_node_index, traced_nodes);

  // Oczekiwana liczba węzłów: 9.
  size_t count = HashMap__size(traced_nodes);
  TEST_ASSERT(count == 9, name);

  // Weryfikacja, że wszystkie oczekiwane indeksy są w mapie i mają poprawny
  // hash
  size_t expected_indices[] = {0, 1, 2, 5, 6, 13, 14, 29, 30};
  for (size_t i = 0; i < 9; ++i) {
    size_t idx = expected_indices[i];
    void *traced_hash_ptr = HashMap__get(traced_nodes, idx);
    const uint8_t *original_hash = MerkleTree__get_node(tree, idx);

    TEST_ASSERT(traced_hash_ptr != NULL, "Trace: Missing expected node");
    if (traced_hash_ptr) {
      TEST_ASSERT(memcmp(traced_hash_ptr, original_hash, tree->node_size) == 0,
                  "Trace: Hash mismatch");
    }
  }

  HashMap__drop(traced_nodes);
  MerkleTree__drop(tree);
  Memory__drop(memory);
  ChallengeId__drop(challenge_id);
}

// Złoty Wzorzec: Używamy stałych parametrów, które pozwolą szybko znaleźć
// nonce. W testach Rust użyto: chunk_count: 16, chunk_size: 64,
// difficulty_bits: 8.
const size_t PROOF_TEST_CHUNK_COUNT = 16;
const size_t PROOF_TEST_CHUNK_SIZE = 64;
const size_t PROOF_TEST_DIFFICULTY = 8;
const size_t PROOF_TEST_MEMORY_SIZE =
    PROOF_TEST_CHUNK_COUNT * PROOF_TEST_CHUNK_SIZE; // 1024

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

  // 2. Jeden cały bajt zero, drugi bajt 0x01 (00000001)
  uint8_t c[] = {0x00, 0x01, 0x00, 0x00};
  TEST_ASSERT(Proof__leading_zeros(c, 4) == 15, name);

  // 3. Brak zerowych bajtów, pierwszy bajt 0x10 (00010000)
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

  // Budowanie drzewa
  MerkleTree__compute_leaf_hashes(merkle_tree, challenge_id, memory);
  MerkleTree__compute_intermediate_nodes(merkle_tree, challenge_id);

  // Wyszukiwanie Proof.
  // Uwaga: Proof__search w C jest implementowany sekwencyjnie.
  Proof *proof = Proof__search(config, challenge_id, memory, merkle_tree);

  // Sprawdzenie weryfikacji. W Rust jest to asercja.
  if (proof) {
    VerificationError err = Proof__verify(proof);
    if (err != VerificationError__Ok) {
      // Weryfikacja nie powiodła się
      fprintf(stderr,
              "!!! BLAD: Proof verification failed with error code: %d\n", err);
      Proof__drop(proof);
      proof = NULL;
    }
  }

  // Zwolnienie zasobów pamięci i drzewa Merkle
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
    // Sprawdzenie podstawowych danych
    TEST_ASSERT(proof->config.difficulty_bits == PROOF_TEST_DIFFICULTY, name);
    TEST_ASSERT(proof->nonce != 0, name);

    // Sprawdzenie czy wszystkie wymagane klucze są obecne
    TEST_ASSERT(HashMap__size(proof->leaf_antecedents) ==
                    proof->config.search_length,
                name);
    // Liczba węzłów w otwarciu drzewa powinna być zbliżona do L * 2
    TEST_ASSERT(
        HashMap__size(proof->tree_opening) > proof->config.search_length, name);

    Proof__drop(proof);
  }
}

// =================================================================
// FUNKCJA GŁÓWNA TESTÓW
// =================================================================

int main() {
  printf("--- Uruchamianie testów Itsuku ---\n\n");

  // GRUPA 1: KONFIGURACJA I ALOKACJA
  test_config_defaults();
  test_challenge_id_allocation();
  test_merkle_node_size();
  test_memory_allocation();

  printf("\n--- Zakończono testy alokacji i konfiguracji ---\n");

  // GRUPA 2: FUNKCJE INDEKSUJĄCE
  test_indexing_argon2();
  test_indexing_phi_variants();

  printf("\n--- Zakończono testy indeksowania ---\n");

  // GRUPA 3: TESTY FUNKCJONALNE PAMIĘCI
  test_element_operations();
  test_memory_build_chunk_determinism();
  test_trace_element_reproducibility();
  test_memory_build_chunk_determinism_rust_ref();

  printf("\n--- Zakończono testy rdzenia pamięci ---\n");

  // GRUPA 4: FUNKCJONALNOŚĆ MERKLE TREE (DODANA/URUCHOMIONA)
  test_merkle_tree_allocation();
  test_merkle_root_matches_rust();
  test_merkle_trace_node();

  printf("\n--- Zakończono testy Merkle Tree ---\n");

  // GRUPA 5: FUNKCJONALNOŚĆ PROOF-OF-WORK (NOWA GRUPA)
  test_proof_leading_zeros();
  test_proof_search_and_verify_success();

  printf("\n--- Zakończono testy Proof-of-Work ---\n");

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
