/*
 * PQ-Schemes implemenation
 * (C) 2022 Simon Gärtner
 * (C) 2022 Sebastian Ramacher
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "oqs-integration.h"

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/oids.h>

#include <array>
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

    std::string_view to_string(PQSignatureScheme scheme) {
      return ALL_ENTRIES[static_cast<uint32_t>(scheme)].oqs_name;
    }

    std::string_view to_human_readable_string(PQSignatureScheme scheme) {
      return ALL_ENTRIES[static_cast<uint32_t>(scheme)].human_name;
    }

    PQSignatureScheme from_string(const std::string& name) {
      for (const auto& entry : ALL_ENTRIES) {
        if (entry.oqs_name == name || entry.human_name == name) {
          return entry.scheme;
        }
      }

      throw Lookup_Error("Unable to lookup PQ signature scheme for " + name);
    }

    OQS_SIG get_sig(PQSignatureScheme scheme) {
      const auto oqs_name = to_string(scheme);
      OQS_SIG* ptr        = OQS_SIG_new(oqs_name.data());
      if (!ptr) {
        throw Lookup_Error("Unable to lookup PQ signature scheme " + std::string{oqs_name});
      }
      OQS_SIG ret = *ptr;
      OQS_SIG_free(ptr);
      return ret;
    }

    PQSignatureScheme from_oid(const OID& oid) {
      return from_string(OIDS::oid2str_or_throw(oid));
    }
  } // namespace

  /* Verification Operation Class */
  class PQ_Verify_Operation final : public PK_Ops::Verification {
  public:
    /**
     * Destructor
     */
    virtual ~PQ_Verify_Operation() = default;

    /**
     * Constructor
     * @param key contains private key
     * @param params contains pq-scheme specific parameters
     * @param pq_scheme_choice enum, which defines the pq-scheme
     */
    PQ_Verify_Operation(const PQ_PublicKey& key) : m_key(key) {}

    /**
     * Function is_valid_signature verifies a signature using a pq public key and
     * returns if the signature with the corresponding public key is valid or not.
     * Library oqs is used for verifying process.
     * @param sig contains signature
     * @param sig_len contains signature length
     * @return return if the signature is valid or not (true or false)
     */
    bool is_valid_signature(const uint8_t sig[], size_t sig_len) override {
      return OQS_SIG_verify(&m_key.m_sig, m_msg.data(), m_msg.size(), sig, sig_len,
                            m_key.m_public.data()) == OQS_SUCCESS;
    }

    /**
     * Function update can be used to update the message member-variable in the
     * PQ_Sign_Operation class.
     * @param msg new message
     * @param msg_len length of the new message
     */
    void update(const uint8_t msg[], size_t msg_len) override {
      m_msg.reserve(m_msg.size() + msg_len);
      m_msg.insert(m_msg.end(), msg, msg + msg_len);
    }

  protected:
    std::vector<uint8_t> m_msg;
    const PQ_PublicKey& m_key;
  };

  class PQ_Sign_Operation final : public PK_Ops::Signature {
  public:
    /**
     * Destructor
     */
    virtual ~PQ_Sign_Operation() = default;

    /**
     * Constructor
     * @param key contains private key
     * @param params contains pq-scheme specific parameters
     * @param msg contains message which should get signed
     * @param pq_scheme_choice enum, which defines the pq-scheme
     */
    explicit PQ_Sign_Operation(const PQ_PrivateKey& key) : m_key(key) {}

    /**
     * Function sign signs a message using a pq private key and saves the signature.
     * Library oqs is used for signing process.
     * @param rng not used
     * @return secure_vector<uint8_t> return signature in form of a secure vector
     */
    secure_vector<uint8_t> sign(RandomNumberGenerator& /*rng*/) override {
      /* create buffer, so pq_keygen can put key in the buffer - no copying needed */
      std::size_t length = signature_length();
      secure_vector<uint8_t> signature(length);

      const auto status = OQS_SIG_sign(&m_key.m_sig, signature.data(), &length, m_msg.data(),
                                       m_msg.size(), m_key.m_private.data());
      if (status != OQS_SUCCESS) {
        throw Internal_Error("OQS_SIG_sign failed for an unknown reason!");
      }
      signature.resize(length);
      return signature;
    }

    /**
     * Function update can be used to update the message member-variable in the
     * PQ_Sign_Operation class.
     * @param msg new message
     * @param msg_len length of the new message
     */
    void update(const uint8_t msg[], size_t msg_len) override {
      m_msg.reserve(m_msg.size() + msg_len);
      m_msg.insert(m_msg.end(), msg, msg + msg_len);
    }

    /**
     * Function signature_length returns the length of the signature
     * @return size_t return signature length
     */
    size_t signature_length() const override {
      return m_key.m_sig.length_signature;
    }

  private:
    std::vector<uint8_t> m_msg;
    const PQ_PrivateKey& m_key;
  };

  /* --- Public Key --- */

  PQ_PublicKey::PQ_PublicKey(PQSignatureScheme scheme) : m_sig(get_sig(scheme)), m_scheme(scheme) {}

  PQ_PublicKey::~PQ_PublicKey() {}

  std::string PQ_PublicKey::algo_name() const {
    return std::string{to_human_readable_string(m_scheme)};
  }

  std::vector<uint8_t> PQ_PublicKey::public_key_bits() const {
    std::vector<uint8_t> output;
    DER_Encoder(output).encode(m_public, ASN1_Type::OctetString);
    return output;
  }

  AlgorithmIdentifier PQ_PublicKey::algorithm_identifier() const {
    return AlgorithmIdentifier(get_oid(), AlgorithmIdentifier::USE_EMPTY_PARAM);
  }

  PQ_PublicKey::PQ_PublicKey(const AlgorithmIdentifier& alg_id,
                             const std::vector<uint8_t>& key_bits)
    : PQ_PublicKey(from_oid(alg_id.get_oid())) {
    BER_Decoder(key_bits).decode(m_public, ASN1_Type::OctetString);
  }

  PQ_PublicKey::PQ_PublicKey(const PQ_PublicKey& other) = default;

  std::unique_ptr<PK_Ops::Verification>
  PQ_PublicKey::create_verification_op(const std::string&, const std::string&) const {
    return std::make_unique<Botan::PQ_Verify_Operation>(*this);
  }

  bool PQ_PublicKey::check_key(RandomNumberGenerator&, bool) const {
    return true;
  }

  size_t PQ_PublicKey::estimated_strength() const {
    switch (m_sig.claimed_nist_level) {
    case 3:
    case 4:
      return 192;
    case 5:
      return 256;
    default:
      return 128;
    }
  }

  size_t PQ_PublicKey::key_length() const {
    return m_sig.length_public_key;
  }

  /* --- Private Key --- */

  PQ_PrivateKey::PQ_PrivateKey(PQSignatureScheme scheme) : PQ_PublicKey(scheme) {
    m_private.resize(m_sig.length_secret_key);
    m_public.resize(m_sig.length_public_key);

    const auto status = OQS_SIG_keypair(&m_sig, m_public.data(), m_private.data());
    if (status != OQS_SUCCESS) {
      throw Internal_Error("OQS_SIG_keypair failed for an unknown reason!");
    }
  }

  PQ_PrivateKey::PQ_PrivateKey(const std::string& algorith_name)
    : PQ_PublicKey(from_string(algorith_name)) {
    m_private.resize(m_sig.length_secret_key);
    m_public.resize(m_sig.length_public_key);

    const auto status = OQS_SIG_keypair(&m_sig, m_public.data(), m_private.data());
    if (status != OQS_SUCCESS) {
      throw Internal_Error("OQS_SIG_keypair failed for an unknown reason!");
    }
  }

  PQ_PrivateKey::PQ_PrivateKey(const AlgorithmIdentifier& alg_id,
                               const secure_vector<uint8_t>& key_bits)
    : PQ_PublicKey(from_oid(alg_id.get_oid())) {
    BER_Decoder(key_bits)
        .decode(m_private, ASN1_Type::OctetString)
        .decode(m_public, ASN1_Type::OctetString);
  }

  PQ_PrivateKey::~PQ_PrivateKey() {}

  secure_vector<uint8_t> PQ_PrivateKey::private_key_bits() const {
    return DER_Encoder()
        .encode(m_private, ASN1_Type::OctetString)
        .encode(m_public, ASN1_Type::OctetString)
        .get_contents();
  }

  std::unique_ptr<Public_Key> PQ_PrivateKey::public_key() const {
    return std::make_unique<Botan::PQ_PublicKey>(*this);
  }

  std::unique_ptr<PK_Ops::Signature> PQ_PrivateKey::create_signature_op(RandomNumberGenerator&,
                                                                        const std::string&,
                                                                        const std::string&) const {
    return std::make_unique<Botan::PQ_Sign_Operation>(*this);
  }

  size_t PQ_PrivateKey::key_length() const {
    return m_sig.length_secret_key + m_sig.length_public_key;
  }
} // namespace Botan