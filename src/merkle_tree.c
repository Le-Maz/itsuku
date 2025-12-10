#include "merkle_tree.h"
#include "memory.h"
#include <blake3.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Stała z Rust: 1.0 dla Element Hash Cost
const double MEMORY_COST_CX = 1.0;
const int BITS_PER_BYTE = 8;

// =================================================================
// MERKLE TREE FUNCTIONS
// =================================================================

size_t MerkleTree__calculate_node_size(const Config *config) {
  double search_length = (double)config->search_length;
  double difficulty = (double)config->difficulty_bits;

  // Rust: let log_operand = MEMORY_COST_CX * search_length + (search_length *
  // 0.5).ceil();
  double log_operand =
      MEMORY_COST_CX * search_length + ceil(search_length * 0.5);

  // Rust: let log_value = (1.0 + log_operand).log2();
  double log_value = log2(1.0 + log_operand);

  // Rust: ((difficulty + log_value + 6.0) * 0.125).ceil() as usize
  // 0.125 to 1/8. Wzór: ceil( (d + log2(...) + 6) / 8 )
  double node_size_double =
      ceil((difficulty + log_value + 6.0) / (double)BITS_PER_BYTE);

  return (size_t)node_size_double;
}

MerkleTree *MerkleTree__new(Config config) {
  MerkleTree *tree = (MerkleTree *)malloc(sizeof(MerkleTree));
  if (!tree)
    return NULL;

  tree->config = config;
  tree->node_size = MerkleTree__calculate_node_size(&config);

  size_t total_elements = config.chunk_count * config.chunk_size;
  // Rust: nodes_count = 2 * total_elements - 1
  size_t nodes_count = 2 * total_elements - 1;
  size_t total_bytes = nodes_count * tree->node_size;

  // Flat storage for all tree nodes (leaves and intermediate nodes)
  tree->nodes = (uint8_t *)calloc(total_bytes, 1);
  if (!tree->nodes) {
    free(tree);
    return NULL;
  }
  tree->nodes_len = total_bytes;

  return tree;
}

void MerkleTree__drop(MerkleTree *self) {
  if (self) {
    free(self->nodes);
    free(self);
  }
}

static uint8_t *MerkleTree__get_node_mut(MerkleTree *self, size_t index) {
  // Przekształcenie indeksu węzła na zakres bajtów
  size_t offset = index * self->node_size;
  if (offset + self->node_size > self->nodes_len) {
    return NULL;
  }
  return &self->nodes[offset];
}

const uint8_t *MerkleTree__get_node(const MerkleTree *self, size_t index) {
  size_t offset = index * self->node_size;
  if (offset + self->node_size > self->nodes_len) {
    return NULL;
  }
  return &self->nodes[offset];
}

void MerkleTree__compute_leaf_hash(const ChallengeId *challenge_id,
                                   const Element *element, size_t node_size,
                                   uint8_t *output) {
  uint8_t element_bytes[ELEMENT_SIZE];
  Element__to_le_bytes(element, element_bytes);

  blake3_hasher S;
  blake3_hasher_init(&S);

  // hashowanie: element_bytes || challenge_id->bytes
  blake3_hasher_update(&S, element_bytes, ELEMENT_SIZE);
  blake3_hasher_update(&S, challenge_id->bytes, challenge_id->bytes_len);

  blake3_hasher_finalize(&S, output, node_size);
}

void MerkleTree__compute_leaf_hashes(MerkleTree *self,
                                     const ChallengeId *challenge_id,
                                     const Memory *memory) {
  size_t element_count = self->config.chunk_count * self->config.chunk_size;
  size_t node_size = self->node_size;

  // W Rust: Leaves start at index element_count - 1
  // Total nodes: 2N - 1. Leaves are at indices N-1 to 2N-2.
  size_t first_leaf = element_count - 1;

  for (size_t i = 0; i < element_count; ++i) {
    size_t node_index = first_leaf + i;

    const Element *element =
        Memory__get((Memory *)memory,
                    i); // Rzutowanie const ze względu na implementację w C
    if (!element)
      return;

    uint8_t *node = MerkleTree__get_node_mut(self, node_index);
    if (!node)
      return;

    MerkleTree__compute_leaf_hash(challenge_id, element, node_size, node);
  }
}

void MerkleTree__children_of(size_t index, size_t *left_index,
                             size_t *right_index) {
  *left_index = 2 * index + 1;
  *right_index = 2 * index + 2;
}

void MerkleTree__compute_intermediate_nodes(MerkleTree *self,
                                            const ChallengeId *challenge_id) {
  size_t total_elements = self->config.chunk_count * self->config.chunk_size;
  size_t node_size = self->node_size;

  // Iteracja wstecz od ostatniego węzła rodzica (N-2) do korzenia (0)
  for (size_t parent_index = total_elements - 2; parent_index > 0;
       --parent_index) {
    size_t left_index, right_index;
    MerkleTree__children_of(parent_index, &left_index, &right_index);

    const uint8_t *left_node = MerkleTree__get_node(self, left_index);
    const uint8_t *right_node = MerkleTree__get_node(self, right_index);
    uint8_t *parent_node = MerkleTree__get_node_mut(self, parent_index);

    if (!left_node || !right_node || !parent_node)
      return;

    // Obliczanie hasha pośredniego węzła: left || right || challenge_id->bytes
    blake3_hasher S;
    blake3_hasher_init(&S);

    blake3_hasher_update(&S, left_node, node_size);
    blake3_hasher_update(&S, right_node, node_size);
    blake3_hasher_update(&S, challenge_id->bytes, challenge_id->bytes_len);

    blake3_hasher_finalize(&S, parent_node, node_size);
  }

  // Obliczenie korzenia (index 0), jeśli istnieje
  if (total_elements > 0) {
    size_t left_index, right_index;
    MerkleTree__children_of(0, &left_index, &right_index);

    const uint8_t *left_node = MerkleTree__get_node(self, left_index);
    const uint8_t *right_node = MerkleTree__get_node(self, right_index);
    uint8_t *root_node = MerkleTree__get_node_mut(self, 0);

    if (!left_node || !right_node || !root_node)
      return;

    blake3_hasher S;
    blake3_hasher_init(&S);

    blake3_hasher_update(&S, left_node, node_size);
    blake3_hasher_update(&S, right_node, node_size);
    blake3_hasher_update(&S, challenge_id->bytes, challenge_id->bytes_len);

    blake3_hasher_finalize(&S, root_node, node_size);
  }
}

/**
 * @brief Kopiuje i wstawia hash węzła do mapy.
 * @param self Wskaźnik na MerkleTree.
 * @param nodes Mapa docelowa.
 * @param idx Indeks węzła.
 */
static void MerkleTree__insert_node_copy(const MerkleTree *self, HashMap nodes,
                                         size_t idx) {
  const uint8_t *node = MerkleTree__get_node(self, idx);
  if (node) {
    // Musimy zaalokować kopię, ponieważ HashMap przejmie własność nad
    // wskaźnikiem.
    uint8_t *copy = (uint8_t *)malloc(self->node_size);
    if (copy) {
      memcpy(copy, node, self->node_size);
      // HashMap__insert: klucz (size_t) -> wskaźnik na bajty (void*)
      HashMap__insert(nodes, idx, copy);
    }
  }
}

void MerkleTree__trace_node(const MerkleTree *self, size_t index,
                            HashMap nodes) {
  size_t total_nodes = self->nodes_len / self->node_size;
  if (index >= total_nodes) {
    return;
  }

  // 1. Dodaj bieżący węzeł
  MerkleTree__insert_node_copy(self, nodes, index);

  if (index == 0) {
    return; // Osiągnięto korzeń
  }

  // 2. Dodaj rodzeństwo (sibling)
  // Jeśli index jest parzysty, rodzeństwo to index - 1. Jeśli nieparzysty,
  // index + 1.
  size_t sibling_index = (index % 2 == 0) ? index - 1 : index + 1;
  MerkleTree__insert_node_copy(self, nodes, sibling_index);

  // 3. Rekurencyjnie na rodzicu
  size_t parent_index = (index - 1) / 2;
  MerkleTree__trace_node(self, parent_index, nodes);
}
