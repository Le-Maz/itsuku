#include "itsuku.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// =================================================================
// POMOCNICY
// =================================================================

/**
 * @brief Konwertuje 4 bajty w formacie Little Endian na uint32_t.
 * Odtwarza u32::from_le_bytes(seed_bytes) z Rust.
 */
static uint32_t le_bytes_to_u32(const uint8_t bytes[4]) {
  // Little Endian: bytes[0] to najmniej znaczący bajt (LSB)
  uint32_t result = (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
                    ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
  return result;
}

// =================================================================
// calculate_argon2_index
// RFC 9106, Section 3.4.2 (Odwzorowanie Rust lib.rs)
// =================================================================

size_t calculate_argon2_index(uint8_t seed_bytes[4], size_t original_index) {
  // Rust: let seed_integer_value: u64 = u32::from_le_bytes(seed_bytes) as u64;
  uint64_t seed_integer_value = le_bytes_to_u32(seed_bytes);

  // Rust: let x = (seed_integer_value.wrapping_mul(seed_integer_value)) >> 32;
  // Mnożenie 32-bitowej liczby podniesionej do kwadratu mieści się w uint64_t.
  uint64_t x = (seed_integer_value * seed_integer_value) >> 32;

  // Rust: let y = ((original_index as u64).wrapping_mul(x)) >> 32;
  // original_index (i) jest rozszerzany do u64.
  uint64_t i_u64 = (uint64_t)original_index;
  uint64_t y = (i_u64 * x) >> 32;

  // Rust: let z = (original_index as u64).wrapping_sub(1).wrapping_sub(y);
  // Operacje na bezstronnych uint64_t w C naturalnie się zawijają
  // (wraparound), co jest równoważne wrapping_sub w Rust.
  // Z logicznego punktu widzenia Itsuku, original_index jest zawsze > y.
  uint64_t z = (i_u64 - 1) - y;

  // Rust: z as usize
  return (size_t)z;
}

// =================================================================
// calculate_phi_variant_index
// Odwzorowanie Rust lib.rs
// =================================================================

size_t calculate_phi_variant_index(size_t original_index, size_t argon2_index,
                                   size_t variant_identifier) {
  // W Itsuku budowanie pamięci odbywa się dla i >= n, gdzie n jest
  // antecedent_count. Zatem oryginal_index >= n (zazwyczaj n >= 4), więc
  // original_index jest wystarczająco duże.
  if (original_index == 0) {
    return 0;
  }

  size_t index;

  // Rust: match variant_identifier % 12
  switch (variant_identifier % 12) {
  case 0:
    // phi_0(i) = i - 1
    index = original_index - 1;
    break;

  case 1:
    // phi_1(i) = phi(i) (wynik Argon2)
    index = argon2_index;
    break;

  case 2:
    // phi_2(i) = (phi(i) + i) / 2
    index = (argon2_index + original_index) / 2;
    break;

  case 3:
    // phi_3(i) = 7 * i / 8
    index = (original_index * 7) / 8;
    break;

  case 4:
    // phi_4(i) = (phi(i) + 3 * i) / 4
    index = (argon2_index + original_index * 3) / 4;
    break;

  case 5:
    // phi_5(i) = (phi(i) + 5 * i) / 8
    index = (argon2_index + original_index * 5) / 8;
    break;

  case 6:
    // phi_6(i) = 3 * i / 4
    index = (original_index * 3) / 4;
    break;

  case 7:
    // phi_7(i) = i / 2
    index = original_index / 2;
    break;

  case 8:
    // phi_8(i) = i / 4
    index = original_index / 4;
    break;

  case 9:
    // phi_9(i) = 0
    index = 0;
    break;

  case 10:
    // phi_10(i) = (7 * phi(i)) / 8
    index = (argon2_index * 7) / 8;
    break;

  case 11:
    // phi_11(i) = (7 * i) / 8
    index = (original_index * 7) / 8;
    break;

  default:
    // Nieosiągalne
    abort();
  }

  // Wymóg Itsuku: 0 <= phi_k(i) < i.
  // Zapewniamy, że indeks nie przekracza maksymalnej dopuszczalnej wartości.
  if (index >= original_index) {
    index = original_index - 1; // Zabezpieczenie
  }

  return index;
}