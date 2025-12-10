#include "proof.h"
#include "memory.h"
#include <blake3.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define OMEGA_HASH_SIZE 64 /**< Blake2b-512 output size */
#define BITS_PER_BYTE 8

/**
 * @brief Retrieves a copy of an Element from full memory.
 *
 * Used by Proof__search to simulate MemoryType::get_element.
 */
static Element Memory__get_element_copy_for_search(void *data, size_t index) {
  const Memory *mem = (const Memory *)data;
  const Element *elem_ptr = Memory__get((Memory *)mem, index);
  if (elem_ptr) {
    return *elem_ptr;
  }
  return Element__zero();
}

/**
 * @brief Retrieves a copy of an Element from a partial memory HashMap.
 *
 * Used by Proof__verify to safely reconstruct Elements without segfaults.
 */
static Element HashMap__get_element_copy_for_verify(void *data, size_t index) {
  HashMap map = (HashMap)data;
  Element *element_ptr = (Element *)HashMap__get(map, index);
  if (element_ptr) {
    return *element_ptr;
  }
  return Element__zero();
}

/**
 * @brief Converts the first 8 bytes of a hash to a uint64_t (Little Endian).
 */
static uint64_t u64_from_hash_le(const uint8_t hash[OMEGA_HASH_SIZE]) {
  return u64_from_le_bytes(hash);
}

/**
 * @brief Counts the number of leading zero bits in a byte array.
 */
size_t Proof__leading_zeros(const uint8_t *array, size_t size) {
  size_t counter = 0;
  for (size_t i = 0; i < size; ++i) {
    if (array[i] == 0) {
      counter += 8;
    } else {
      unsigned int byte = array[i];
      int leading_zeros_in_byte = 0;
      for (int bit = 7; bit >= 0; --bit) {
        if ((byte >> bit) & 1) {
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
 * @brief Calculates the Omega (Ω) hash without allocating new buffers.
 *
 * @param omega_out Buffer for resulting Omega hash (OMEGA_HASH_SIZE bytes)
 * @param selected_leaves_out Buffer for selected leaf indices (size L)
 * @param path_hashes_out Buffer for path hashes (L+1 * OMEGA_HASH_SIZE)
 * @param config Proof configuration
 * @param challenge_id Challenge identifier
 * @param memory_wrapper Access wrapper for memory
 * @param merkle_tree_wrapper Access wrapper for Merkle tree (unused)
 * @param root_hash Root hash of Merkle tree
 * @param memory_size Total number of memory elements
 * @param nonce Current nonce to evaluate
 */
void Proof__calculate_omega_no_alloc(
    uint8_t omega_out[OMEGA_HASH_SIZE], size_t selected_leaves_out[],
    uint8_t path_hashes_out[][OMEGA_HASH_SIZE], const Config *config,
    const ChallengeId *challenge_id, PartialMemory_Wrapper memory_wrapper,
    PartialMerkleTree_Wrapper merkle_tree_wrapper [[maybe_unused]],
    const uint8_t root_hash[OMEGA_HASH_SIZE], size_t memory_size,
    uint64_t nonce) {
  size_t L = config->search_length;

  blake3_hasher hasher;
  blake3_hasher_init(&hasher);

  size_t *selected_leaves = selected_leaves_out;
  uint8_t (*path)[OMEGA_HASH_SIZE] = path_hashes_out;

  // Step 4: Initialize Y0 = HS(nonce || root_hash || challenge_id)
  uint8_t nonce_bytes[8];
  u64_to_le_bytes(nonce, nonce_bytes);
  blake3_hasher_update(&hasher, nonce_bytes, 8);
  blake3_hasher_update(&hasher, root_hash, OMEGA_HASH_SIZE);
  blake3_hasher_update(&hasher, challenge_id->bytes, challenge_id->bytes_len);
  blake3_hasher_finalize(&hasher, path[0], OMEGA_HASH_SIZE);
  blake3_hasher_reset(&hasher);

  // Step 5: Iteratively compute path hashes
  for (size_t j = 0; j < L; ++j) {
    const uint8_t *prev_hash = path[j];
    uint64_t hash_val = u64_from_hash_le(prev_hash);
    size_t index = (size_t)(hash_val % memory_size);
    selected_leaves[j] = index;

    Element element = memory_wrapper.get_element(memory_wrapper.data, index);
    Element__bitxor_assign__bytes(&element, challenge_id->bytes,
                                  challenge_id->bytes_len);

    uint8_t element_bytes[ELEMENT_SIZE];
    Element__to_le_bytes(&element, element_bytes);

    blake3_hasher_update(&hasher, prev_hash, OMEGA_HASH_SIZE);
    blake3_hasher_update(&hasher, element_bytes, ELEMENT_SIZE);
    blake3_hasher_finalize(&hasher, path[j + 1], OMEGA_HASH_SIZE);
    blake3_hasher_reset(&hasher);
  }

  // Step 6: Back sweep to compute final Omega hash
  for (size_t k = L; k >= 1; --k) {
    blake3_hasher_update(&hasher, path[k], OMEGA_HASH_SIZE);
  }

  Element element_from_hash;
  memcpy(element_from_hash.data, path[0], OMEGA_HASH_SIZE);
  Element__bitxor_assign__bytes(&element_from_hash, challenge_id->bytes,
                                challenge_id->bytes_len);

  uint8_t element_bytes[ELEMENT_SIZE];
  Element__to_le_bytes(&element_from_hash, element_bytes);
  blake3_hasher_update(&hasher, element_bytes, ELEMENT_SIZE);

  blake3_hasher_finalize(&hasher, omega_out, OMEGA_HASH_SIZE);
}

/**
 * @brief Allocates buffers and calculates Omega hash.
 *
 * @param omega_out Output buffer for Omega hash
 * @param selected_leaves_len_out Output length of selected leaves
 * @param selected_leaves_out Output array of selected leaf indices
 * @param path_len_out Output length of path hashes
 * @param path_hashes_out Output 2D array of path hashes
 * @param config Proof configuration
 * @param challenge_id Challenge identifier
 * @param memory_wrapper Memory access abstraction
 * @param merkle_tree_wrapper Merkle tree access abstraction (unused)
 * @param root_hash Root hash of the Merkle tree
 * @param memory_size Number of memory elements
 * @param nonce Nonce to evaluate
 */
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
  size_t *selected_leaves = (size_t *)malloc(L * sizeof(size_t));
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

  Proof__calculate_omega_no_alloc(
      omega_out, selected_leaves, path, config, challenge_id, memory_wrapper,
      merkle_tree_wrapper, root_hash, memory_size, nonce);

  *selected_leaves_len_out = L;
  *selected_leaves_out = selected_leaves;
  *path_len_out = L + 1;
  *path_hashes_out = (uint8_t **)path;
}

/**
 * @brief Searches sequentially for a nonce that satisfies the PoW difficulty.
 *
 * @param config Proof configuration
 * @param challenge_id Challenge identifier
 * @param memory Full memory
 * @param merkle_tree Merkle tree of memory elements
 * @return Dynamically allocated Proof if found, otherwise NULL
 */
Proof *Proof__search(Config config, const ChallengeId *challenge_id,
                     const Memory *memory, const MerkleTree *merkle_tree) {
  const uint8_t *root_hash_ptr = MerkleTree__get_node(merkle_tree, 0);
  if (!root_hash_ptr)
    return NULL;

  uint8_t root_hash[OMEGA_HASH_SIZE];
  memcpy(root_hash, root_hash_ptr, merkle_tree->node_size);
  if (merkle_tree->node_size < OMEGA_HASH_SIZE) {
    memset(root_hash + merkle_tree->node_size, 0,
           OMEGA_HASH_SIZE - merkle_tree->node_size);
  }

  size_t memory_size = config.chunk_count * config.chunk_size;
  size_t L = config.search_length;

  size_t *selected_leaves = (size_t *)malloc(L * sizeof(size_t));
  uint8_t (*path_hashes)[OMEGA_HASH_SIZE] =
      (uint8_t (*)[OMEGA_HASH_SIZE])malloc((L + 1) * OMEGA_HASH_SIZE);
  if (!selected_leaves || !path_hashes) {
    if (selected_leaves)
      free(selected_leaves);
    if (path_hashes)
      free(path_hashes);
    return NULL;
  }

  PartialMemory_Wrapper memory_wrapper = {
      .data = (void *)memory,
      .get_element = Memory__get_element_copy_for_search};

  uint8_t omega[OMEGA_HASH_SIZE];
  for (uint64_t nonce = 1; nonce < ULLONG_MAX; ++nonce) {
    Proof__calculate_omega_no_alloc(omega, selected_leaves, path_hashes,
                                    &config, challenge_id, memory_wrapper,
                                    (PartialMerkleTree_Wrapper){0}, root_hash,
                                    memory_size, nonce);

    if (Proof__leading_zeros(omega, OMEGA_HASH_SIZE) < config.difficulty_bits) {
      continue;
    }

    Proof *proof = (Proof *)malloc(sizeof(Proof));
    if (!proof) {
      free(selected_leaves);
      free(path_hashes);
      return NULL;
    }

    proof->config = config;
    proof->challenge_id = *challenge_id;
    proof->nonce = nonce;
    proof->leaf_antecedents = HashMap__new(free);
    proof->tree_opening = HashMap__new(free);

    for (size_t i = 0; i < L; ++i) {
      size_t leaf_index = selected_leaves[i];
      size_t node_index = memory_size - 1 + leaf_index;

      Element *antecedents = NULL;
      size_t antecedent_count =
          Memory__trace_element(memory, leaf_index, &antecedents);
      if (antecedent_count > 0) {
        HashMap__insert(proof->leaf_antecedents, leaf_index, antecedents);
      } else if (antecedents) {
        free(antecedents);
      }

      MerkleTree__trace_node(merkle_tree, node_index, proof->tree_opening);
    }

    free(selected_leaves);
    free(path_hashes);
    return proof;
  }

  free(selected_leaves);
  free(path_hashes);
  return NULL;
}

/**
 * @brief Frees a dynamically allocated Proof.
 */
void Proof__drop(Proof *self) {
  if (self) {
    HashMap__drop(self->leaf_antecedents);
    HashMap__drop(self->tree_opening);
    free(self);
  }
}

/**
 * @brief Verifies a Proof against its challenge and configuration.
 *
 * @param self Proof to verify
 * @return VerificationError__Ok if valid, otherwise an error code
 */
VerificationError Proof__verify(const Proof *self) {
  const Config *config = &self->config;
  const ChallengeId *challenge_id = &self->challenge_id;
  size_t node_size = MerkleTree__calculate_node_size(config);
  size_t memory_size = config->chunk_count * config->chunk_size;
  VerificationError err = VerificationError__Ok;
  HashMap merkle_nodes = NULL;

  HashMap partial_memory = HashMap__new(free);
  if (!partial_memory)
    return VerificationError__RequiredElementMissing;

  HashMapIterator ante_iter = HashMapIterator__new(self->leaf_antecedents);
  size_t leaf_index;
  void *antecedents_ptr;

  while (HashMapIterator__next(&ante_iter, &leaf_index, &antecedents_ptr)) {
    const Element *antecedents = (const Element *)antecedents_ptr;
    size_t element_index_in_chunk = leaf_index % config->chunk_size;
    size_t ante_count = (element_index_in_chunk < config->antecedent_count)
                            ? 1
                            : config->antecedent_count;

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

  merkle_nodes = HashMap__new(free);
  if (!merkle_nodes) {
    err = VerificationError__RequiredElementMissing;
    goto cleanup;
  }

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

    HashMap__insert(merkle_nodes, node_index, leaf_hash);
  }

  HashMapIterator opening_iter = HashMapIterator__new(self->tree_opening);
  size_t node_idx;
  void *opened_hash_ptr;
  while (HashMapIterator__next(&opening_iter, &node_idx, &opened_hash_ptr)) {
    if (!HashMap__get(merkle_nodes, node_idx)) {
      uint8_t *copy = (uint8_t *)malloc(node_size);
      if (!copy) {
        err = VerificationError__RequiredElementMissing;
        goto cleanup;
      }
      memcpy(copy, opened_hash_ptr, node_size);
      HashMap__insert(merkle_nodes, node_idx, copy);
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

  PartialMemory_Wrapper verify_memory_wrapper = {
      .data = partial_memory,
      .get_element = HashMap__get_element_copy_for_verify};

  PartialMerkleTree_Wrapper merkle_tree_wrapper = {
      .data = merkle_nodes,
      .get_node = NULL // Not used in calculate_omega
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

  if (Proof__leading_zeros(omega, OMEGA_HASH_SIZE) < config->difficulty_bits) {
    err = VerificationError__DifficultyNotMet;
    goto free_and_cleanup_omega;
  }

free_and_cleanup_omega:
  free(selected_leaves);
  free(path_hashes);

cleanup:
  HashMap__drop(merkle_nodes);
  HashMap__drop(partial_memory);

  return err;
}
