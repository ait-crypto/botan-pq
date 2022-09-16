/*
 * PQ-Schemes implemenation
 * (C) 2022 Simon Gärtner
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "pq_mapping.h"

#include <array>
#include <oqs/sig.h>
#include <string_view>

namespace Botan {
  namespace {
    struct Entry {
      PQSignatureScheme scheme;
      std::string_view human_name;
      std::string_view oqs_name;
    };

    static constexpr std::array<Entry, 51> ALL_ENTRIES{{
        {PQSignatureScheme::dilithium2, "Dilithium 2", OQS_SIG_alg_dilithium_2},
        {PQSignatureScheme::dilithium3, "Dilithium 3", OQS_SIG_alg_dilithium_3},
        {PQSignatureScheme::dilithium5, "Dilithium 5", OQS_SIG_alg_dilithium_5},
        {PQSignatureScheme::dilithium2_aes, "Dilithium 2 AES", OQS_SIG_alg_dilithium_2_aes},
        {PQSignatureScheme::dilithium3_aes, "Dilithium 3 AES", OQS_SIG_alg_dilithium_3_aes},
        {PQSignatureScheme::dilithium5_aes, "Dilithium 5 AES", OQS_SIG_alg_dilithium_5_aes},
        {PQSignatureScheme::picnic_l1_fs, "Picnic L1 FS", OQS_SIG_alg_picnic_L1_FS},
        {PQSignatureScheme::picnic_l1_full, "Picnic L1 Full", OQS_SIG_alg_picnic_L1_full},
        {PQSignatureScheme::picnic_l3_fs, "Picnic L3 FS", OQS_SIG_alg_picnic_L3_FS},
        {PQSignatureScheme::picnic_l3_full, "Picnic L3 Full", OQS_SIG_alg_picnic_L3_full},
        {PQSignatureScheme::picnic_l5_fs, "Picnic L5 FS", OQS_SIG_alg_picnic_L5_FS},
        {PQSignatureScheme::picnic_l5_full, "Picnic L5 Full", OQS_SIG_alg_picnic_L5_full},
        {PQSignatureScheme::picnic3_l1, "Picnic3 L1", OQS_SIG_alg_picnic3_L1},
        {PQSignatureScheme::picnic3_l3, "Picnic3 L3", OQS_SIG_alg_picnic3_L3},
        {PQSignatureScheme::picnic3_l5, "Picnic3 L5", OQS_SIG_alg_picnic3_L5},
        {PQSignatureScheme::sphincs_haraka_128f_robust, "SPHINCS+-Haraka-128f-robust",
         OQS_SIG_alg_sphincs_haraka_128f_robust},
        {PQSignatureScheme::sphincs_haraka_128f_simple, "SPHINCS+-Haraka-128f-simple",
         OQS_SIG_alg_sphincs_haraka_128f_simple},
        {PQSignatureScheme::sphincs_haraka_128s_robust, "SPHINCS+-Haraka-128s-robust",
         OQS_SIG_alg_sphincs_haraka_128s_robust},
        {PQSignatureScheme::sphincs_haraka_128s_simple, "SPHINCS+-Haraka-128s-simple",
         OQS_SIG_alg_sphincs_haraka_128s_simple},
        {PQSignatureScheme::sphincs_haraka_192f_robust, "SPHINCS+-Haraka-192f-robust",
         OQS_SIG_alg_sphincs_haraka_192f_robust},
        {PQSignatureScheme::sphincs_haraka_192f_simple, "SPHINCS+-Haraka-192f-simple",
         OQS_SIG_alg_sphincs_haraka_192f_simple},
        {PQSignatureScheme::sphincs_haraka_192s_robust, "SPHINCS+-Haraka-192s-robust",
         OQS_SIG_alg_sphincs_haraka_192s_robust},
        {PQSignatureScheme::sphincs_haraka_192s_simple, "SPHINCS+-Haraka-192s-simple",
         OQS_SIG_alg_sphincs_haraka_192s_simple},
        {PQSignatureScheme::sphincs_haraka_256f_robust, "SPHINCS+-Haraka-256f-robust",
         OQS_SIG_alg_sphincs_haraka_256f_robust},
        {PQSignatureScheme::sphincs_haraka_256f_simple, "SPHINCS+-Haraka-256f-simple",
         OQS_SIG_alg_sphincs_haraka_256f_simple},
        {PQSignatureScheme::sphincs_haraka_256s_robust, "SPHINCS+-Haraka-256s-robust",
         OQS_SIG_alg_sphincs_haraka_256s_robust},
        {PQSignatureScheme::sphincs_haraka_256s_simple, "SPHINCS+-Haraka-256s-simple",
         OQS_SIG_alg_sphincs_haraka_256s_simple},
        {PQSignatureScheme::sphincs_sha256_128f_robust, "SPHINCS+-SHA256-128f-robust",
         OQS_SIG_alg_sphincs_sha256_128f_robust},
        {PQSignatureScheme::sphincs_sha256_128f_simple, "SPHINCS+-SHA256-128f-simple",
         OQS_SIG_alg_sphincs_sha256_128f_simple},
        {PQSignatureScheme::sphincs_sha256_128s_robust, "SPHINCS+-SHA256-128s-robust",
         OQS_SIG_alg_sphincs_sha256_128s_robust},
        {PQSignatureScheme::sphincs_sha256_128s_simple, "SPHINCS+-SHA256-128s-simple",
         OQS_SIG_alg_sphincs_sha256_128s_simple},
        {PQSignatureScheme::sphincs_sha256_192f_robust, "SPHINCS+-SHA256-192f-robust",
         OQS_SIG_alg_sphincs_sha256_192f_robust},
        {PQSignatureScheme::sphincs_sha256_192f_simple, "SPHINCS+-SHA256-192f-simple",
         OQS_SIG_alg_sphincs_sha256_192f_simple},
        {PQSignatureScheme::sphincs_sha256_192s_robust, "SPHINCS+-SHA256-192s-robust",
         OQS_SIG_alg_sphincs_sha256_192s_robust},
        {PQSignatureScheme::sphincs_sha256_192s_simple, "SPHINCS+-SHA256-192s-simple",
         OQS_SIG_alg_sphincs_sha256_192s_simple},
        {PQSignatureScheme::sphincs_sha256_256f_robust, "SPHINCS+-SHA256-256f-robust",
         OQS_SIG_alg_sphincs_sha256_256f_robust},
        {PQSignatureScheme::sphincs_sha256_256f_simple, "SPHINCS+-SHA256-256f-simple",
         OQS_SIG_alg_sphincs_sha256_256f_simple},
        {PQSignatureScheme::sphincs_sha256_256s_robust, "SPHINCS+-SHA256-256s-robust",
         OQS_SIG_alg_sphincs_sha256_256s_robust},
        {PQSignatureScheme::sphincs_sha256_256s_simple, "SPHINCS+-SHA256-256s-simple",
         OQS_SIG_alg_sphincs_sha256_256s_simple},
        {PQSignatureScheme::sphincs_shake256_128f_robust, "SPHINCS+-SHAKE256-128f-robust",
         OQS_SIG_alg_sphincs_shake256_128f_robust},
        {PQSignatureScheme::sphincs_shake256_128f_simple, "SPHINCS+-SHAKE256-128f-simple",
         OQS_SIG_alg_sphincs_shake256_128f_simple},
        {PQSignatureScheme::sphincs_shake256_128s_robust, "SPHINCS+-SHAKE256-128s-robust",
         OQS_SIG_alg_sphincs_shake256_128s_robust},
        {PQSignatureScheme::sphincs_shake256_128s_simple, "SPHINCS+-SHAKE256-128s-simple",
         OQS_SIG_alg_sphincs_shake256_128s_simple},
        {PQSignatureScheme::sphincs_shake256_192f_robust, "SPHINCS+-SHAKE256-192f-robust",
         OQS_SIG_alg_sphincs_shake256_192f_robust},
        {PQSignatureScheme::sphincs_shake256_192f_simple, "SPHINCS+-SHAKE256-192f-simple",
         OQS_SIG_alg_sphincs_shake256_192f_simple},
        {PQSignatureScheme::sphincs_shake256_192s_robust, "SPHINCS+-SHAKE256-192s-robust",
         OQS_SIG_alg_sphincs_shake256_192s_robust},
        {PQSignatureScheme::sphincs_shake256_192s_simple, "SPHINCS+-SHAKE256-192s-simple",
         OQS_SIG_alg_sphincs_shake256_192s_simple},
        {PQSignatureScheme::sphincs_shake256_256f_robust, "SPHINCS+-SHAKE256-256f-robust",
         OQS_SIG_alg_sphincs_shake256_256f_robust},
        {PQSignatureScheme::sphincs_shake256_256f_simple, "SPHINCS+-SHAKE256-256f-simple",
         OQS_SIG_alg_sphincs_shake256_256f_simple},
        {PQSignatureScheme::sphincs_shake256_256s_robust, "SPHINCS+-SHAKE256-256s-robust",
         OQS_SIG_alg_sphincs_shake256_256s_robust},
        {PQSignatureScheme::sphincs_shake256_256s_simple, "SPHINCS+-SHAKE256-256s-simple",
         OQS_SIG_alg_sphincs_shake256_256s_simple},
    }};
  } // namespace

  const char* to_string(PQSignatureScheme scheme) {
    return ALL_ENTRIES[static_cast<uint32_t>(scheme)].oqs_name.data();
  }

  const char* to_human_readable_string(PQSignatureScheme scheme) {
    return ALL_ENTRIES[static_cast<uint32_t>(scheme)].human_name.data();
  }

  std::optional<PQSignatureScheme> from_string(const char* name) {
    for (const auto& entry : ALL_ENTRIES) {
      if (entry.oqs_name == name || entry.human_name == name) {
        return std::make_optional(entry.scheme);
      }
    }

    return std::nullopt;
  }
} // namespace Botan