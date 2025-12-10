#include "../src/config.h"
#include "../src/memory.h"
#include "../src/merkle_tree.h"
#include "itsuku_tests.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Funkcja pomocnicza dla testów Merkle Tree (konieczna, ponieważ używa logiki
// testowej)
MerkleTree *MerkleTree__build_for_test(Config config, ChallengeId *challenge_id,
                                       Memory *memory) {
  MerkleTree *tree = MerkleTree__new(config);
  if (!tree)
    return NULL;

  MerkleTree__compute_leaf_hashes(tree, challenge_id, memory);
  MerkleTree__compute_intermediate_nodes(tree, challenge_id);

  return tree;
}

// Złoty Wzorzec z testu Rust
const uint8_t EXPECTED_ROOT_HASH[] = {0xbf, 0x8d, 0xbf, 0xaf, 0xcc};
const size_t EXPECTED_ROOT_HASH_LEN = 5;

// =================================================================
// GRUPA 4: FUNKCJONALNOŚĆ MERKLE TREE
// =================================================================

void test_merkle_node_size() {
  const char *name = "Merkle Node Size Calculation";
  printf("  [Test] %s\n", name);
  Config c = Config__default();

  c.difficulty_bits = 70;
  size_t node_size_70 = MerkleTree__calculate_node_size(&c);
  TEST_ASSERT(node_size_70 == 10, name);

  c.difficulty_bits = 24;
  c.search_length = 9;
  size_t node_size_24 = MerkleTree__calculate_node_size(&c);
  TEST_ASSERT(node_size_24 == 5, name);
}

void test_merkle_tree_allocation() {
  const char *name = "Merkle Tree Allocation and Drop";
  printf("  [Test] %s\n", name);
  Config config = Config__default();
  config.chunk_count = 2;
  config.chunk_size = 8;
  size_t total_elements = config.chunk_count * config.chunk_size;

  MerkleTree *tree = MerkleTree__new(config);

  TEST_ASSERT(tree != NULL, name);
  if (tree) {
    size_t expected_node_size = MerkleTree__calculate_node_size(&config);
    size_t expected_nodes_count = 2 * total_elements - 1;
    size_t expected_total_bytes = expected_nodes_count * expected_node_size;

    TEST_ASSERT(tree->node_size == expected_node_size, name);
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

  MerkleTree *tree = MerkleTree__build_for_test(config, challenge_id, memory);

  if (tree) {
    const uint8_t *root_hash = MerkleTree__get_node(tree, 0);

    TEST_ASSERT(root_hash != NULL, name);
    if (root_hash) {
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

  size_t element_index = 15;
  size_t leaf_node_index =
      (config.chunk_count * config.chunk_size) - 1 + element_index;

  HashMap traced_nodes = HashMap__new(free);
  MerkleTree__trace_node(tree, leaf_node_index, traced_nodes);

  size_t count = HashMap__size(traced_nodes);
  TEST_ASSERT(count == 9, name);

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
