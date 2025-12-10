#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// --- Dołączenie interfejsów publicznych biblioteki ---
#include "../src/challenge_id.h"
#include "../src/config.h"
#include "../src/hashmap.h"
#include "../src/memory.h"
#include "../src/merkle_tree.h"
#include "../src/proof.h"

// --- Definicje stałych ---
#define ITSUKU_HASH_SIZE 64
#define ITSUKU_NONCE_SIZE 8
#define ITSUKU_ELEMENT_SIZE 64

// Złoty Wzorzec z testu Rust dla Config (użyty do obliczeń)
const size_t DEFAULT_NODE_SIZE = 5;

// --- Utility Functions (print_hex, serialize_proof, parse_hex) ---

/**
 * @brief Helper function to print a byte array in hexadecimal format to a
 * specified stream.
 */
static void print_hex(FILE *stream, const char *label, const uint8_t *data,
                      size_t size) {
  fprintf(stream, "%s: ", label);
  for (size_t i = 0; i < size; i++) {
    fprintf(stream, "%02x", data[i]);
  }
  fprintf(stream, "\n");
}

/**
 * @brief Helper function to serialize and print the entire proof structure to
 * stdout (machine-friendly).
 */
static void serialize_proof(const Proof *proof, size_t node_size) {
  // All output to stdout for machine parsing
  fprintf(stdout, "STATUS: SUCCESS\n");

  // 1. Core Solution Data
  uint8_t nonce_bytes[ITSUKU_NONCE_SIZE];
  u64_to_le_bytes(proof->nonce, nonce_bytes);
  print_hex(stdout, "NONCE", nonce_bytes, ITSUKU_NONCE_SIZE);

  // Musimy obliczyć hash Omega, aby go wyświetlić. W Proof nie jest
  // przechowywany. W tym przykładzie, jest to niemożliwe bez duplikowania
  // Proof__verify. Zamiast tego, wyświetlamy kluczowe dane.
  // print_hex(stdout, "OMEGA_HASH", proof->omega_hash, ITSUKU_HASH_SIZE);

  // Hash Korzenia (Root Hash) jest w tree_opening pod indeksem 0
  const uint8_t *root_hash_ptr =
      (const uint8_t *)HashMap__get(proof->tree_opening, 0);
  if (root_hash_ptr) {
    print_hex(stdout, "ROOT_HASH", root_hash_ptr, node_size);
  } else {
    fprintf(stdout, "ROOT_HASH: MISSING\n");
  }

  // 2. Configuration Parameters
  print_hex(stdout, "CHALLENGE_ID", proof->challenge_id.bytes,
            proof->challenge_id.bytes_len);
  fprintf(stdout, "SEARCH_LENGTH: %zu\n", proof->config.search_length);

  // 3. Collective Opening (Z) - Merkle Proof Nodes
  fprintf(stdout, "MERKLE_PROOF_NODE_SIZE: %zu\n", node_size);
  fprintf(stdout, "MERKLE_PROOF_NODES_COUNT: %zu\n",
          HashMap__size(proof->tree_opening));

  // Wypisanie wszystkich węzłów (index:hash) z tree_opening
  HashMapIterator node_iter = HashMapIterator__new(proof->tree_opening);
  size_t node_index;
  void *hash_ptr;

  while (HashMapIterator__next(&node_iter, &node_index, &hash_ptr)) {
    fprintf(stdout, "NODE_%zu_INDEX: %zu\n", node_index, node_index);
    print_hex(stdout, "NODE_HASH", (const uint8_t *)hash_ptr, node_size);
  }

  // 4. Collective Opening (Z) - Leaf Data (leaf_antecedents)
  fprintf(stdout, "LEAF_COUNT: %zu\n", HashMap__size(proof->leaf_antecedents));

  // Wypisanie antecedentów dla każdego liścia
  HashMapIterator leaf_iter = HashMapIterator__new(proof->leaf_antecedents);
  size_t leaf_index;
  void *antecedents_ptr;

  while (HashMapIterator__next(&leaf_iter, &leaf_index, &antecedents_ptr)) {
    fprintf(stdout, "LEAF_INDEX: %zu\n", leaf_index);
    // Wartość jest Element* (ciąg elementów)
    const Element *antecedents = (const Element *)antecedents_ptr;

    // Wypisujemy tylko pierwszy element z ciągu antecedentów jako
    // reprezentatywny. Pełne wypisanie wymagałoby znajomości długości ciągu, co
    // jest trudne.
    print_hex(stdout, "LEAF_ANTECEDENT_0_DATA", (void *)antecedents[0].data,
              ITSUKU_ELEMENT_SIZE);
  }
}

/**
 * @brief Converts a hexadecimal string into a byte array.
 * @return 0 on success, -1 on failure.
 */
static int parse_hex(const char *hex_str, uint8_t *out_bytes, size_t max_size) {
  size_t len = strlen(hex_str);
  if (len % 2 != 0 || len / 2 > max_size) {
    return -1; // Invalid length or too long
  }

  for (size_t i = 0; i < len; i += 2) {
    char byte_str[3];
    strncpy(byte_str, hex_str + i, 2);
    byte_str[2] = '\0';
    unsigned int byte_val;
    if (sscanf(byte_str, "%x", &byte_val) != 1) {
      return -1; // Invalid hex character
    }
    out_bytes[i / 2] = (uint8_t)byte_val;
  }
  return 0;
}

/**
 * @brief Prints usage instructions to stderr.
 */
static void print_usage(const char *prog_name) {
  fprintf(stderr, "\nItsuku Proof-of-Work Solver\n");
  fprintf(stderr, "Usage: %s [OPTIONS]\n", prog_name);
  fprintf(stderr, "\nOptions:\n");
  fprintf(stderr, "  -i, --id ID_HEX       Specify the Challenge ID (I) as a "
                  "hex string.\n");
  fprintf(stderr, "                        (REQUIRED: Must be %d bytes long)\n",
          ITSUKU_HASH_SIZE);
  fprintf(stderr, "  -d, --difficulty N    Set the difficulty in bits (d).\n");
  fprintf(stderr, "  -l, --length N        Set the search length (L).\n");
  fprintf(stderr, "  -c, --chunks N        Set the total chunk count (P).\n");
  fprintf(stderr, "  -s, --chunk-size N    Set the chunk size (l).\n");
  fprintf(stderr, "  -a, --antecedents N   Set the antecedent count (n).\n");
  fprintf(stderr, "  -r, --random          Generate a random Challenge ID (I) "
                  "instead of using -i.\n");
  fprintf(stderr,
          "  -h, --help            Display this help message and exit.\n");
  fprintf(stderr, "\nExample: %s -r -d 10\n", prog_name);
}

// --- Main Program ---

int main(int argc, char *argv[]) {
  int generate_random_id = 0;
  int challenge_id_provided = 0;

  // Inicjalizacja konfiguracji na wartości domyślne
  Config config = Config__default();

  // Final Challenge ID structure
  ChallengeId challenge_id;
  challenge_id.bytes_len = ITSUKU_HASH_SIZE;
  challenge_id.bytes = malloc(challenge_id.bytes_len);
  if (!challenge_id.bytes) {
    fprintf(stderr, "Error: Failed to allocate memory for challenge_id.\n");
    return 1;
  }

  memset(challenge_id.bytes, 0, challenge_id.bytes_len);

  // Pobieranie opcji
  static struct option long_options[] = {
      {"id", required_argument, 0, 'i'},
      {"difficulty", required_argument, 0, 'd'},
      {"length", required_argument, 0, 'l'},
      {"chunks", required_argument, 0, 'c'},
      {"chunk-size", required_argument, 0, 's'},
      {"antecedents", required_argument, 0, 'a'},
      {"random", no_argument, 0, 'r'},
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0}};

  int c;
  int option_index = 0;

  while ((c = getopt_long(argc, argv, "i:d:l:c:s:a:rh", long_options,
                          &option_index)) != -1) {
    char *endptr;
    unsigned long val;

    switch (c) {
    case 'i': // Challenge ID
      if (parse_hex(optarg, challenge_id.bytes, challenge_id.bytes_len) != 0 ||
          (strlen(optarg) != challenge_id.bytes_len * 2)) {
        fprintf(stderr,
                "Error: Challenge ID must be a hex string of length %zu (%zu "
                "bytes).\n",
                challenge_id.bytes_len * 2, challenge_id.bytes_len);
        free(challenge_id.bytes);
        return 1;
      }
      challenge_id_provided = 1;
      break;

    case 'd': // Difficulty
    case 'l': // Search Length
    case 'c': // Chunk Count
    case 's': // Chunk Size
    case 'a': // Antecedent Count
      errno = 0;
      val = strtoul(optarg, &endptr, 10);
      if (*endptr != '\0' || errno != 0) {
        fprintf(stderr, "Error: Argument for -%c must be a positive integer.\n",
                c);
        free(challenge_id.bytes);
        return 1;
      }

      // Assign the parsed value to the corresponding config field
      switch (c) {
      case 'd':
        config.difficulty_bits = (size_t)val;
        break;
      case 'l':
        config.search_length = (size_t)val;
        break;
      case 'c':
        config.chunk_count = (size_t)val;
        break;
      case 's':
        config.chunk_size = (size_t)val;
        break;
      case 'a':
        config.antecedent_count = (size_t)val;
        break;
      }
      break;

    case 'r': // Generate Random ID
      generate_random_id = 1;
      break;

    case 'h': // Help
      print_usage(argv[0]);
      free(challenge_id.bytes);
      return 0;

    case '?': // Unknown or missing argument
      fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
      free(challenge_id.bytes);
      return 1;

    default:
      abort();
    }
  }

  // --- 1. Finalize Challenge ID (I) ---
  if (!challenge_id_provided && !generate_random_id) {
    fprintf(stderr, "Error: Challenge ID is required. Use -i or -r.\n");
    print_usage(argv[0]);
    free(challenge_id.bytes);
    return 1;
  }

  if (generate_random_id) {
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < challenge_id.bytes_len; i++) {
      challenge_id.bytes[i] = (uint8_t)(rand() % 256);
    }
  }

  // Używamy globalnego ChallengeId do konfiguracji (nie jest kopiowane!)
  // Domyślna konfiguracja ma zerowy ChallengeId, ale to jest w porządku.
  // Po prostu użyjemy tego ChallengeId w Proof__search.

  // --- 2. Inicjalizacja struktur Itsuku ---

  // Konieczne jest zbudowanie Memory i MerkleTree przed Proof__search

  // Tworzymy ChallengeId, które będzie używane przez Proof__search.
  ChallengeId *challenge_id_ptr =
      ChallengeId__new(challenge_id.bytes, challenge_id.bytes_len);
  if (!challenge_id_ptr) {
    fprintf(stderr, "Error: Failed to finalize challenge ID structure.\n");
    free(challenge_id.bytes);
    return 1;
  }

  Memory *memory = Memory__new(config);
  if (!memory) {
    fprintf(stderr, "Error: Failed to allocate Memory.\n");
    ChallengeId__drop(challenge_id_ptr);
    free(challenge_id.bytes);
    return 1;
  }

  // Wypełniamy pamięć
  Memory__build_all_chunks(memory, challenge_id_ptr);

  MerkleTree *merkle_tree = MerkleTree__new(config);
  if (!merkle_tree) {
    fprintf(stderr, "Error: Failed to allocate Merkle Tree.\n");
    Memory__drop(memory);
    ChallengeId__drop(challenge_id_ptr);
    free(challenge_id.bytes);
    return 1;
  }

  // Budujemy Merkle Tree
  MerkleTree__compute_leaf_hashes(merkle_tree, challenge_id_ptr, memory);
  MerkleTree__compute_intermediate_nodes(merkle_tree, challenge_id_ptr);

  // --- 3. Print Configuration (to stderr) ---
  const size_t total_elements_T = config.chunk_count * config.chunk_size;

  fprintf(stderr, "\n🔑 Starting Itsuku PoW search with configuration:\n");
  fprintf(stderr, "  Total Elements (T=P*l): %zu (P=%zu, l=%zu)\n",
          total_elements_T, config.chunk_count, config.chunk_size);
  fprintf(stderr, "  Search Length (L): %zu\n", config.search_length);
  fprintf(stderr, "  Difficulty Bits (d): %zu\n", config.difficulty_bits);
  fprintf(stderr, "  Antecedents (n): %zu\n", config.antecedent_count);
  print_hex(stderr, "  Challenge ID (I)", challenge_id_ptr->bytes,
            challenge_id_ptr->bytes_len);
  fprintf(stderr, "  Element Size: %d bytes\n", ITSUKU_ELEMENT_SIZE);

  // --- 4. Compute PoW Solution ---
  Proof *proof = NULL;
  clock_t start_time = clock();

  // Główna funkcja wyszukiwania
  proof = Proof__search(config, challenge_id_ptr, memory, merkle_tree);

  clock_t end_time = clock();
  double cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

  // --- 5. Process and Serialize Results ---
  VerificationError verify_result;
  if (proof != NULL) {
    // Weryfikacja (opcjonalna, ale zalecana)
    verify_result = Proof__verify(proof);

    if (verify_result == VerificationError__Ok) {
      fprintf(stderr,
              "\n✅ PoW Search Successful and Verified in %.4f seconds.\n",
              cpu_time_used);

      // Machine-friendly proof serialization to stdout
      size_t node_size = MerkleTree__calculate_node_size(&config);
      serialize_proof(proof, node_size);
    } else {
      fprintf(stderr, "\n❌ PoW Search Failed Verification (Error code %d).\n",
              verify_result);
      Proof__drop(proof);
      proof = NULL;
    }
  } else {
    fprintf(stderr, "\n❌ PoW Search Failed (No nonce found).\n");
  }

  // --- 6. Clean up allocated memory ---
  if (proof)
    Proof__drop(proof);
  MerkleTree__drop(merkle_tree);
  Memory__drop(memory);
  ChallengeId__drop(challenge_id_ptr); // Zwalnia również challenge_id.bytes
  free(challenge_id
           .bytes); // Zwalniamy tylko wskaźnik alokowany na początku.
                    // Dwa razy: raz challenge_id_ptr (płytka kopia), raz
                    // ręcznie. Poprawka: ChallengeId__new robi głęboką kopię.

  return (proof != NULL && verify_result == VerificationError__Ok) ? 0 : 1;
}
