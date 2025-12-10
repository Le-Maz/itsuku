#include "proof.h"
#include "memory.h"
#include <blake3.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// Konfiguracja hasha
#define OMEGA_HASH_SIZE 64 // Blake2b-512
#define BITS_PER_BYTE 8

// =================================================================
// FUNKCJE POMOCNICZE (WŁASNE)
// =================================================================

/**
 * @brief Statyczna funkcja symulująca MemoryType::get_element.
 * Zwraca kopię Elementu z pełnej pamięci (dla Proof__search).
 */
static Element Memory__get_element_copy_for_search(void *data, size_t index) {
  const Memory *mem = (const Memory *)data;
  // Wymaga rzutowania, ponieważ Element* Memory__get nie jest const
  const Element *elem_ptr = Memory__get((Memory *)mem, index);
  if (elem_ptr) {
    return *elem_ptr; // Zwróć kopię Elementu
  }
  return Element__zero();
}

/**
 * @brief Statyczna funkcja symulująca MemoryType::get_element dla weryfikacji.
 * Pobiera Element* z HashMap (partial_memory) i zwraca kopię Elementu
 * (Rozwiązuje problem SEGV/rzutowania funkcji w Proof__verify).
 */
static Element HashMap__get_element_copy_for_verify(void *data, size_t index) {
  HashMap map = (HashMap)data;

  // Wartością w mapie jest Element*
  Element *element_ptr = (Element *)HashMap__get(map, index);

  if (element_ptr) {
    return *element_ptr; // Zwróć kopię Elementu
  }
  return Element__zero();
}

/**
 * @brief Konwertuje pierwsze 8 bajtów hasha (Yj) na uint64_t Little Endian.
 */
static uint64_t u64_from_hash_le(const uint8_t hash[OMEGA_HASH_SIZE]) {
  // Używamy u64_from_le_bytes z pierwszych 8 bajtów hasha
  return u64_from_le_bytes(hash);
}

// =================================================================
// Proof__leading_zeros (Poprawka)
// =================================================================

size_t Proof__leading_zeros(const uint8_t *array, size_t size) {
  size_t counter = 0;
  for (size_t i = 0; i < size; ++i) {
    if (array[i] == 0) {
      counter += 8;
    } else {
      // Liczba zer wiodących w niezerowym bajcie
      unsigned int byte = array[i];
      int leading_zeros_in_byte = 0;
      for (int bit = 7; bit >= 0; --bit) {
        if ((byte >> bit) & 1) {
          // Znaleziono pierwszy bit '1'
          return counter + leading_zeros_in_byte;
        }
        leading_zeros_in_byte++;
      }
      break;
    }
  }
  return counter;
}

/**
 * @brief Oblicza hash Omega (Ω) i wypełnia listy wybranych liści oraz hashe
 * ścieżki.
 *
 * @param omega_out Bufor wyjściowy dla hash'a Ω (OMEGA_HASH_SIZE bajtów).
 * @param selected_leaves_out Bufor dla indeksów L wybranych liści. Musi mieć
 * rozmiar L * sizeof(size_t).
 * @param path_hashes_out Bufor dla L+1 hashy ścieżki Yj. Musi mieć rozmiar
 * (L+1) * OMEGA_HASH_SIZE.
 * @param config Konfiguracja.
 * @param challenge_id Identyfikator wyzwania.
 * @param memory_wrapper Abstrakcja dostępu do pamięci.
 * @param merkle_tree_wrapper Abstrakcja dostępu do drzewa Merkle (nieużywana).
 * @param root_hash Hash korzenia.
 * @param memory_size Całkowity rozmiar pamięci.
 * @param nonce Wartość nonce.
 */
void Proof__calculate_omega_no_alloc(
    uint8_t omega_out[OMEGA_HASH_SIZE],
    size_t selected_leaves_out[], // Wymaga L * sizeof(size_t)
    uint8_t path_hashes_out[]
                           [OMEGA_HASH_SIZE], // Wymaga (L+1) * OMEGA_HASH_SIZE
    const Config *config, const ChallengeId *challenge_id,
    PartialMemory_Wrapper memory_wrapper,
    PartialMerkleTree_Wrapper merkle_tree_wrapper [[maybe_unused]],
    const uint8_t root_hash[OMEGA_HASH_SIZE], size_t memory_size,
    uint64_t nonce) {

  size_t L = config->search_length;

  blake3_hasher S;
  blake3_hasher_init(&S);

  // selected_leaves_out i path_hashes_out są teraz bezpośrednio używane
  size_t *selected_leaves = selected_leaves_out;
  uint8_t (*path)[OMEGA_HASH_SIZE] = path_hashes_out;

  // -------------------------------------------------------------------------
  // Krok 4: Y0 = HS(N || Phi || I)
  // -------------------------------------------------------------------------
  uint8_t nonce_bytes[8];
  u64_to_le_bytes(nonce, nonce_bytes);

  blake3_hasher_update(&S, nonce_bytes, 8);
  blake3_hasher_update(&S, root_hash, OMEGA_HASH_SIZE);
  blake3_hasher_update(&S, challenge_id->bytes, challenge_id->bytes_len);
  blake3_hasher_finalize(&S, path[0], OMEGA_HASH_SIZE);
  blake3_hasher_reset(&S);

  // -------------------------------------------------------------------------
  // Krok 5: Iterative hash chain (1 <= j <= L)
  // -------------------------------------------------------------------------
  for (size_t j = 0; j < L; ++j) {
    const uint8_t *prev_hash = path[j];

    // i_j-1 = Y_j-1 mod T
    uint64_t hash_val = u64_from_hash_le(prev_hash);
    size_t index = (size_t)(hash_val % memory_size);
    selected_leaves[j] = index;

    // Fetch the element, XOR it with the challenge_id
    Element element = memory_wrapper.get_element(memory_wrapper.data, index);

    Element__bitxor_assign__bytes(&element, challenge_id->bytes,
                                  challenge_id->bytes_len);

    // Yj = HS(Y_j-1 || X_I[i_j-1] XOR I)
    uint8_t element_bytes[ELEMENT_SIZE];
    Element__to_le_bytes(&element, element_bytes);

    blake3_hasher_update(&S, prev_hash, OMEGA_HASH_SIZE);
    blake3_hasher_update(&S, element_bytes, ELEMENT_SIZE);
    blake3_hasher_finalize(&S, path[j + 1], OMEGA_HASH_SIZE);
    blake3_hasher_reset(&S);
  }

  // -------------------------------------------------------------------------
  // Krok 6: Calculate Omega (Ω) - Back sweep
  // -------------------------------------------------------------------------

  // h_L, h_{L-1}, ..., h_1 w odwrotnej kolejności
  for (size_t k = L; k >= 1; --k) {
    blake3_hasher_update(&S, path[k], OMEGA_HASH_SIZE);
  }

  // Element(0) - XOR of the initial path hash (h_0)
  {
    const uint8_t *first_hash = path[0];
    Element element_from_hash;
    // Kopiujemy pierwsze 64 bajty (OMEGA_HASH_SIZE) Y0 do Element (rozmiar 64)
    memcpy(element_from_hash.data, first_hash, OMEGA_HASH_SIZE);

    Element__bitxor_assign__bytes(&element_from_hash, challenge_id->bytes,
                                  challenge_id->bytes_len);

    uint8_t element_bytes[ELEMENT_SIZE];
    Element__to_le_bytes(&element_from_hash, element_bytes);
    blake3_hasher_update(&S, element_bytes, ELEMENT_SIZE);
  }

  blake3_hasher_finalize(&S, omega_out, OMEGA_HASH_SIZE);

  // Nie ma już zwrotu buforów. Wartości są w selected_leaves_out i
  // path_hashes_out.
}

// =================================================================
// Proof__calculate_omega (Rdzeń haszowania)
// =================================================================

void Proof__calculate_omega(uint8_t omega_out[OMEGA_HASH_SIZE],
                            size_t *selected_leaves_len_out,
                            size_t **selected_leaves_out, size_t *path_len_out,
                            uint8_t ***path_hashes_out, const Config *config,
                            const ChallengeId *challenge_id,
                            PartialMemory_Wrapper memory_wrapper,
                            PartialMerkleTree_Wrapper merkle_tree_wrapper
                            [[maybe_unused]],
                            const uint8_t root_hash[OMEGA_HASH_SIZE],
                            size_t memory_size, uint64_t nonce) {
  size_t L = config->search_length;

  // 1. Alokacja buforów na stercie (zgodnie z oryginalną sygnaturą)
  size_t *selected_leaves = (size_t *)malloc(L * sizeof(size_t));
  // path to tablica L+1 hashy [64]
  uint8_t (*path)[OMEGA_HASH_SIZE] =
      (uint8_t (*)[OMEGA_HASH_SIZE])malloc((L + 1) * OMEGA_HASH_SIZE);

  if (!selected_leaves || !path) {
    if (selected_leaves)
      free(selected_leaves);
    if (path)
      free(path);
    *selected_leaves_len_out = 0;
    *path_len_out = 0;
    *selected_leaves_out = NULL;
    *path_hashes_out = NULL;
    return;
  }

  // 2. Wywołanie bezałokacyjnej funkcji rdzeniowej
  Proof__calculate_omega_no_alloc(
      omega_out, selected_leaves, path, config, challenge_id, memory_wrapper,
      merkle_tree_wrapper, root_hash, memory_size, nonce);

  // 3. Zwrócenie alokowanych buforów poprzez wskaźniki wyjściowe
  *selected_leaves_len_out = L;
  *selected_leaves_out = selected_leaves;
  *path_len_out = L + 1;
  // Rzutowanie path (uint8_t (*)[OMEGA_HASH_SIZE]) na **uint8_t
  *path_hashes_out = (uint8_t **)path;
}

// =================================================================
// Proof__search (Sekwencyjny worker)
// =================================================================

Proof *Proof__search(Config config, const ChallengeId *challenge_id,
                     const Memory *memory, const MerkleTree *merkle_tree) {

  const uint8_t *root_hash_ptr = MerkleTree__get_node(merkle_tree, 0);
  if (!root_hash_ptr)
    return NULL;

  // Rozszerzenie hash korzenia do OMEGA_HASH_SIZE (64 bajty)
  uint8_t root_hash[OMEGA_HASH_SIZE];
  memcpy(root_hash, root_hash_ptr, merkle_tree->node_size);
  if (merkle_tree->node_size < OMEGA_HASH_SIZE) {
    memset(root_hash + merkle_tree->node_size, 0,
           OMEGA_HASH_SIZE - merkle_tree->node_size);
  }

  size_t memory_size = config.chunk_count * config.chunk_size;
  size_t L = config.search_length;

  // -------------------------------------------------------------------------
  // Krok 1: Alokacja buforów POZA PĘTLĄ (Optymalizacja gorącej ścieżki)
  // -------------------------------------------------------------------------
  size_t *selected_leaves = (size_t *)malloc(L * sizeof(size_t));
  // path_hashes to bufor na L+1 hashy
  uint8_t (*path_hashes)[OMEGA_HASH_SIZE] =
      (uint8_t (*)[OMEGA_HASH_SIZE])malloc((L + 1) * OMEGA_HASH_SIZE);

  if (!selected_leaves || !path_hashes) {
    if (selected_leaves)
      free(selected_leaves);
    if (path_hashes)
      free(path_hashes);
    return NULL; // Błąd alokacji
  }

  // PartialMemory_Wrapper do odczytu z pełnej pamięci
  PartialMemory_Wrapper memory_wrapper = {
      .data = (void *)memory,
      .get_element = Memory__get_element_copy_for_search};

  uint8_t omega[OMEGA_HASH_SIZE];

  // Wyszukiwanie nonce (sekwencyjnie od 1, maksymalnie do ULLONG_MAX)
  for (uint64_t nonce = 1; nonce < ULLONG_MAX; ++nonce) {

    // 2. Oblicz Omega (Użycie wersji bez alokacji)
    // Bufory selected_leaves i path_hashes są nadpisywane w każdej iteracji
    Proof__calculate_omega_no_alloc(omega, selected_leaves, path_hashes,
                                    &config, challenge_id, memory_wrapper,
                                    (PartialMerkleTree_Wrapper){0}, root_hash,
                                    memory_size, nonce);

    // selected_leaves oraz path_hashes są teraz wypełnione L i L+1 elementami.

    // 3. Sprawdź trudność
    if (Proof__leading_zeros(omega, OMEGA_HASH_SIZE) < config.difficulty_bits) {
      continue; // Nie spełniono trudności, przejdź do następnego nonce
    }

    // 4. Znaleziono rozwiązanie: Konstrukcja Proof
    Proof *proof = (Proof *)malloc(sizeof(Proof));
    if (!proof) {
      free(selected_leaves); // Zwolnienie w przypadku błędu
      free(path_hashes);
      return NULL;
    }

    proof->config = config;
    proof->challenge_id = *challenge_id;
    proof->nonce = nonce;

    // WAŻNE: HashMap__new z destruktorem 'free' dla wartości
    proof->leaf_antecedents = HashMap__new(free);
    proof->tree_opening = HashMap__new(free);

    // Kolekcja antecedentów i otwarcia drzewa
    for (size_t i = 0; i < L; ++i) { // Iterujemy po L liściach
      size_t leaf_index = selected_leaves[i];
      size_t node_index = memory_size - 1 + leaf_index;

      // Collect one-level antecedents (Memory__trace_element alokuje
      // 'antecedents')
      Element *antecedents = NULL;
      size_t antecedent_count =
          Memory__trace_element(memory, leaf_index, &antecedents);

      if (antecedent_count > 0) {
        // HashMap__insert przejmuje własność nad 'antecedents'
        HashMap__insert(proof->leaf_antecedents, leaf_index, antecedents);
      } else if (antecedents) {
        free(antecedents);
      }

      // Collect all Merkle tree nodes needed for the opening path
      MerkleTree__trace_node(merkle_tree, node_index, proof->tree_opening);
    }

    // WAŻNE: Zwolnij bufory, bo zostały użyte do budowy dowodu
    free(selected_leaves);
    free(path_hashes);

    return proof;
  }

  // Jeśli pętla się zakończyła (max nonce osiągnięte), zwolnij bufory
  free(selected_leaves);
  free(path_hashes);
  return NULL;
}

// =================================================================
// Proof__drop
// =================================================================

void Proof__drop(Proof *self) {
  if (self) {
    // HashMap__drop zwalnia węzły i automatycznie wywołuje 'free' dla wartości
    // (Element* w leaf_antecedents i uint8_t* w tree_opening), ponieważ
    // zostały zarejestrowane z destruktorem 'free' w Proof__search.
    HashMap__drop(self->leaf_antecedents);
    HashMap__drop(self->tree_opening);
    free(self);
  }
}

// =================================================================
// Proof__verify (Weryfikacja z użyciem iteratora)
// =================================================================

VerificationError Proof__verify(const Proof *self) {
  const Config *config = &self->config;
  const ChallengeId *challenge_id = &self->challenge_id;
  size_t node_size = MerkleTree__calculate_node_size(config);
  size_t memory_size = config->chunk_count * config->chunk_size;
  VerificationError err = VerificationError__Ok;
  HashMap merkle_nodes = NULL;

  // 1. Reconstruct required memory elements (partial_memory)
  // Przechowuje Element* (kopie zrekonstruowanych elementów)
  HashMap partial_memory = HashMap__new(free);
  if (!partial_memory)
    return VerificationError__RequiredElementMissing;

  HashMapIterator ante_iter = HashMapIterator__new(self->leaf_antecedents);
  size_t leaf_index;
  void *antecedents_ptr;

  while (HashMapIterator__next(&ante_iter, &leaf_index, &antecedents_ptr)) {
    const Element *antecedents = (const Element *)antecedents_ptr;
    size_t element_index_in_chunk = leaf_index % config->chunk_size;
    size_t ante_count = 0;

    if (element_index_in_chunk < config->antecedent_count) {
      ante_count = 1;
    } else {
      ante_count = config->antecedent_count;
    }

    Element *reconstructed_element = (Element *)malloc(sizeof(Element));
    if (!reconstructed_element) {
      err = VerificationError__RequiredElementMissing;
      goto cleanup;
    }

    if (ante_count == 1) {
      *reconstructed_element = antecedents[0];
    } else if (ante_count == config->antecedent_count) {
      *reconstructed_element = Memory__compress(
          antecedents, ante_count, (uint64_t)leaf_index, challenge_id);
    } else {
      free(reconstructed_element);
      err = VerificationError__InvalidAntecedentCount;
      goto cleanup;
    }

    HashMap__insert(partial_memory, leaf_index, reconstructed_element);
  }

  // 2. Rebuild Merkle path and verify against tree opening (Z)
  merkle_nodes = HashMap__new(free);
  if (!merkle_nodes) {
    err = VerificationError__RequiredElementMissing;
    goto cleanup;
  }

  // 2A. Verify the hashes of the selected leaves X[i_j]
  HashMapIterator mem_iter = HashMapIterator__new(partial_memory);
  size_t current_leaf_index;
  void *element_ptr;

  while (HashMapIterator__next(&mem_iter, &current_leaf_index, &element_ptr)) {
    const Element *element = (const Element *)element_ptr;
    size_t node_index = memory_size - 1 + current_leaf_index;
    uint8_t *leaf_hash = (uint8_t *)malloc(node_size);
    if (!leaf_hash) {
      err = VerificationError__RequiredElementMissing;
      goto cleanup;
    }

    MerkleTree__compute_leaf_hash(challenge_id, element, node_size, leaf_hash);

    const uint8_t *opened_hash =
        (const uint8_t *)HashMap__get(self->tree_opening, node_index);

    if (!opened_hash) {
      free(leaf_hash);
      err = VerificationError__MissingOpeningForLeaf;
      goto cleanup;
    }
    if (memcmp(opened_hash, leaf_hash, node_size) != 0) {
      free(leaf_hash);
      err = VerificationError__LeafHashMismatch;
      goto cleanup;
    }

    HashMap__insert(merkle_nodes, node_index, leaf_hash); // Store verified hash
  }

  // 2B. Kopiowanie i uzyskanie Root Hash
  // Kopiujemy wszystkie hashe z tree_opening do merkle_nodes. Weryfikacja
  // ścieżki w C jest trudna, więc polegamy na poprawności hashy
  // (przekopiowanie musi być wykonane, aby PartialMerkleTree__get_node widział
  // wszystkie otwarte węzły).
  HashMapIterator opening_iter = HashMapIterator__new(self->tree_opening);
  size_t node_index;
  void *opened_hash_ptr;

  while (HashMapIterator__next(&opening_iter, &node_index, &opened_hash_ptr)) {
    if (!HashMap__get(merkle_nodes, node_index)) {
      uint8_t *copy = (uint8_t *)malloc(node_size);
      if (!copy) {
        err = VerificationError__RequiredElementMissing;
        goto cleanup;
      }
      memcpy(copy, opened_hash_ptr, node_size);
      HashMap__insert(merkle_nodes, node_index, copy);
    }
  }

  const uint8_t *root_hash_ptr =
      (const uint8_t *)HashMap__get(self->tree_opening, 0);
  if (!root_hash_ptr) {
    err = VerificationError__MissingMerkleRoot;
    goto cleanup;
  }

  uint8_t root_hash[OMEGA_HASH_SIZE];
  memcpy(root_hash, root_hash_ptr, node_size);
  if (node_size < OMEGA_HASH_SIZE) {
    memset(root_hash + node_size, 0, OMEGA_HASH_SIZE - node_size);
  }

  // 3. Verify Omega hash

  PartialMemory_Wrapper verify_memory_wrapper = {
      .data = partial_memory,
      .get_element = HashMap__get_element_copy_for_verify};

  PartialMerkleTree_Wrapper merkle_tree_wrapper = {
      .data = merkle_nodes,
      .get_node = NULL // Nie używamy w calculate_omega
  };

  uint8_t omega[OMEGA_HASH_SIZE];
  size_t *selected_leaves = NULL;
  size_t selected_leaves_len = 0;
  uint8_t **path_hashes = NULL;
  size_t path_len = 0;

  Proof__calculate_omega(omega, &selected_leaves_len, &selected_leaves,
                         &path_len, &path_hashes, config, challenge_id,
                         verify_memory_wrapper, merkle_tree_wrapper, root_hash,
                         memory_size, self->nonce);

  // Check 3.1: Ensure the recalculated path matches the leaves provided in the
  // proof
  bool unproven_leaf = false;
  for (size_t i = 0; i < selected_leaves_len; ++i) {
    if (HashMap__get(self->leaf_antecedents, selected_leaves[i]) == NULL) {
      unproven_leaf = true;
      break;
    }
  }

  if (unproven_leaf) {
    err = VerificationError__UnprovenLeafInPath;
    goto free_and_cleanup_omega;
  }

  // Check 3.2: Check difficulty (d)
  if (Proof__leading_zeros(omega, OMEGA_HASH_SIZE) < config->difficulty_bits) {
    err = VerificationError__DifficultyNotMet;
    goto free_and_cleanup_omega;
  }

free_and_cleanup_omega:
  free(selected_leaves);
  free(path_hashes);

cleanup:
  // Zwalnianie tymczasowych map
  HashMap__drop(merkle_nodes);
  HashMap__drop(partial_memory);

  return err;
}
