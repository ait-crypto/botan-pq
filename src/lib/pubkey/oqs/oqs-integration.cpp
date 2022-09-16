/*
 * PQ-Schemes implemenation
 * (C) 2022 Simon Gärtner
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "oqs-integration.h"
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/oids.h>

namespace Botan {
  namespace {
    OQS_SIG get_sig(PQSignatureScheme scheme) {
      const auto oqs_name = to_string(scheme);
      OQS_SIG* ptr        = OQS_SIG_new(oqs_name);
      if (!ptr) {
        throw Lookup_Error("Unable to lookup PQ signature scheme " + std::string{oqs_name});
      }
      OQS_SIG ret = *ptr;
      OQS_SIG_free(ptr);
      return ret;
    }

    PQSignatureScheme from_name(const std::string& name) {
      const auto scheme = from_string(name.c_str());
      if (!scheme) {
        throw Lookup_Error("Unable to lookup PQ signature scheme for " + name);
      }
      return *scheme;
    }

    PQSignatureScheme from_oid(const OID& oid) {
      return from_name(OIDS::oid2str_or_throw(oid));
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
      // TODO: if!
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
    return to_human_readable_string(m_scheme);
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
    // TODO: if status!
  }

  PQ_PrivateKey::PQ_PrivateKey(const std::string& algorith_name)
    : PQ_PublicKey(from_name(algorith_name)) {
    m_private.resize(m_sig.length_secret_key);
    m_public.resize(m_sig.length_public_key);

    const auto status = OQS_SIG_keypair(&m_sig, m_public.data(), m_private.data());
    // TODO: if status!
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