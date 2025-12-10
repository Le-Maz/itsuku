#include "../src/config.h"
#include "../src/itsuku.h"
#include "../src/memory.h"
#include "itsuku_tests.h"
#include <stdio.h>
#include <string.h>

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

  uint64_t val_a = 0xFFFFFFFFFFFFFFF0UL;
  uint64_t val_b = 0x0000000000000010UL;
  uint64_t val_x = 0xAAAAAAAAAAAAAAAALL;
  uint64_t val_y = 0x5555555555555555LL;

  // Inicjalizacja A i B
  a.data[0] = val_a;
  a.data[1] = val_x;
  b.data[0] = val_b;
  b.data[1] = val_y;

  // 1. Test ADD (Wrapping)
  c = a;
  Element__add_assign(&c, &b);

  TEST_ASSERT(c.data[0] == 0UL, name);
  TEST_ASSERT(c.data[1] == ULLONG_MAX, name);

  // 2. Test XOR
  c = a;
  Element__bitxor_assign(&c, &b);
  TEST_ASSERT(c.data[1] == ULLONG_MAX, name);
}
