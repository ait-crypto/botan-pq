/*
 * PQ-Schemes implemenation
 * (C) 2022 Simon Gärtner
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef PQ_Mapping_H
#define PQ_Mapping_H

#include <botan/asn1_obj.h>
#include <optional>

namespace Botan {
  enum class PQSignatureScheme : uint32_t {
    dilithium2,
    dilithium3,
    dilithium5,
    dilithium2_aes,
    dilithium3_aes,
    dilithium5_aes,
    picnic_l1_fs,
    picnic_l1_full,
    picnic_l3_fs,
    picnic_l3_full,
    picnic_l5_fs,
    picnic_l5_full,
    picnic3_l1,
    picnic3_l3,
    picnic3_l5,
    sphincs_haraka_128f_robust,
    sphincs_haraka_128f_simple,
    sphincs_haraka_128s_robust,
    sphincs_haraka_128s_simple,
    sphincs_haraka_192f_robust,
    sphincs_haraka_192f_simple,
    sphincs_haraka_192s_robust,
    sphincs_haraka_192s_simple,
    sphincs_haraka_256f_robust,
    sphincs_haraka_256f_simple,
    sphincs_haraka_256s_robust,
    sphincs_haraka_256s_simple,
    sphincs_sha256_128f_robust,
    sphincs_sha256_128f_simple,
    sphincs_sha256_128s_robust,
    sphincs_sha256_128s_simple,
    sphincs_sha256_192f_robust,
    sphincs_sha256_192f_simple,
    sphincs_sha256_192s_robust,
    sphincs_sha256_192s_simple,
    sphincs_sha256_256f_robust,
    sphincs_sha256_256f_simple,
    sphincs_sha256_256s_robust,
    sphincs_sha256_256s_simple,
    sphincs_shake256_128f_robust,
    sphincs_shake256_128f_simple,
    sphincs_shake256_128s_robust,
    sphincs_shake256_128s_simple,
    sphincs_shake256_192f_robust,
    sphincs_shake256_192f_simple,
    sphincs_shake256_192s_robust,
    sphincs_shake256_192s_simple,
    sphincs_shake256_256f_robust,
    sphincs_shake256_256f_simple,
    sphincs_shake256_256s_robust,
    sphincs_shake256_256s_simple
  };

  const char* to_string(PQSignatureScheme scheme);
  // PQSignatureScheme from_string(const char* scheme);
  const char* to_human_readable_string(PQSignatureScheme scheme);

  std::optional<PQSignatureScheme> from_string(const char* name);
} // namespace Botan

#endif // PQ_Mapping_H