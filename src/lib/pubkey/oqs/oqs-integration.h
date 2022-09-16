/*
 * PQ-Schemes implemenation
 * (C) 2022 Simon Gärtner
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/pk_ops_impl.h>
#include <botan/pk_keys.h>

#include "pq_mapping.h"
#include <oqs/sig.h>

#ifndef PQ_ALGOS_H
#define PQ_ALGOS_H

namespace Botan {

  class PQ_PrivateKey;
  class PQ_Verify_Operation;
  class PQ_Sign_Operation;

  /**
   * This class represents PQ Public Keys
   */
  class BOTAN_PUBLIC_API(2, 2) PQ_PublicKey : public virtual Public_Key {
  public:
    friend class PQ_Verify_Operation;

    /**
     * Destructor
     */
    virtual ~PQ_PublicKey();

    /**
     * Load a public key
     * @param alg_id the X.509 algorithm identifier
     * @param key_bits DER encoded public key bits
     */
    PQ_PublicKey(const AlgorithmIdentifier& alg_id, const std::vector<uint8_t>& key_bits);

    PQ_PublicKey(const PQ_PublicKey& other);

    /**
     * Return the public key bits
     * @return std::vector<uint8_t> public key bits in vector form
     */
    std::vector<uint8_t> public_key_bits() const override;

    /**
     * Return the key length of the pq public key
     * @return size_t key length
     */
    size_t key_length() const override;

    /**
     * Return the PQ-Algorithm name
     * @return std::string pq-algorithm name
     */
    std::string algo_name() const override;

    /**
     * Return an AlgortimIdentifier which contains the OID and an encoding option
     * @return AlgorithmIdentifier
     */
    AlgorithmIdentifier algorithm_identifier() const override;

    /**
     * Check key checks parameter of the key. Returns always true.
     * @param rng RandomNumberGenerator (not used)
     * @param strong boolean (not used)
     * @return returns always true
     */
    virtual bool check_key(RandomNumberGenerator& rng, bool strong) const override;

    /**
     * Estimated Strength returns the estimated strength of the underlying key.
     * @return estimated strength in bits
     */
    virtual size_t estimated_strength() const override;

    /**
     * Helper Function
     * @param oid
     * @return pq_scheme
     */
    // pq_scheme oid2pq_scheme(OID oid);

    /**
     * This is an internal library function exposed on key types.
     * In almost all cases applications should use wrappers in pubkey.h
     *
     * Return a verification operation for this key/params or throw
     * @param params additional parameters
     * @param provider the provider to use
     */
    virtual std::unique_ptr<PK_Ops::Verification>
    create_verification_op(const std::string& params, const std::string& provider) const override;

  protected:
    OQS_SIG m_sig;
    std::vector<uint8_t> m_public;
    PQSignatureScheme m_scheme;

    /**
     * Decide pq-scheme
     * @param pq_scheme_choice contains enum-value which represents pq-scheme
     */
    PQ_PublicKey(PQSignatureScheme scheme);
  };

  /**
   * This class represents PQ Private Keys
   */
  class BOTAN_PUBLIC_API(2, 2) PQ_PrivateKey : public virtual Private_Key,
                                               public virtual PQ_PublicKey {
  public:
    friend class PQ_Sign_Operation;

    /**
     * Destructor
     */
    virtual ~PQ_PrivateKey();

    /**
     * Generate a new Post Quantum Private Key
     * @param pq_scheme_choice contains which pq-private key should be created
     */
    PQ_PrivateKey(PQSignatureScheme scheme);

    explicit PQ_PrivateKey(const std::string& algorithm_name);

    /**
     * Load a private key
     * @param alg_id the X.509 algorithm identifier
     * @param key_bits DER encoded private key bits
     */
    PQ_PrivateKey(const AlgorithmIdentifier& alg_id, const secure_vector<uint8_t>& key_bits);

    /**
     * Return private key bits
     * @return secure_vector<uint8_t> private key bits in vector form
     */
    secure_vector<uint8_t> private_key_bits() const override;

    /**
     * Return the key length of the pq private key
     * @return size_t key length
     */
    size_t key_length() const override;

    /**
     * Extract the public key from the private key
     * @return std::unique_ptr<Public_Key> return a public key object
     */
    std::unique_ptr<Public_Key> public_key() const override;

    /**
     * This is an internal library function exposed on key types.
     * In almost all cases applications should use wrappers in pubkey.h
     *
     * Return a signature operation for this key/params or throw
     *
     * @param rng a random number generator. The PK_Op may maintain a
     * reference to the RNG and use it many times. The rng must outlive
     * any operations which reference it.
     * @param params additional parameters
     * @param provider the provider to use
     */
    virtual std::unique_ptr<PK_Ops::Signature>
    create_signature_op(RandomNumberGenerator& rng, const std::string& params,
                        const std::string& provider) const override;

  protected:
    secure_vector<uint8_t> m_private;
  };

} // namespace Botan

#endif // PQ_Algos_H
