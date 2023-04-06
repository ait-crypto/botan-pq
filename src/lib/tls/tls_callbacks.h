/*
* TLS Callbacks
* (C) 2016 Matthias Gierlings
*     2016 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CALLBACKS_H_
#define BOTAN_TLS_CALLBACKS_H_

#include <botan/tls_session.h>
#include <botan/tls_alert.h>
#include <botan/dl_group.h>
#include <botan/pubkey.h>
#include <botan/ocsp.h>
#include <optional>
#include <chrono>

namespace Botan {

class Certificate_Store;
class X509_Certificate;

namespace OCSP {

class Response;

}

namespace TLS {

class Handshake_Message;
class Policy;
class Extensions;
class Certificate_Status_Request;

/**
* Encapsulates the callbacks that a TLS channel will make which are due to
* channel specific operations.
*/
class BOTAN_PUBLIC_API(2,0) Callbacks
   {
   public:
       virtual ~Callbacks() = default;

       /**
       * @name Mandatory
       *
       * Those callbacks must be implemented by all applications that use TLS.
       * @{
       */

       /**
       * Mandatory callback: output function
       *
       * The channel will call this with @p data which needs to be sent to the
       * peer (eg, over a socket or some other form of IPC). The array will be
       * overwritten when the function returns so a copy must be made if the
       * data cannot be sent immediately.
       *
       * As an example you could ``send`` to perform a blocking write on a
       * socket, or append the data to a queue managed by your application, and
       * initiate an asynchronous write.

       * For TLS all writes must occur *in the order requested*. For DTLS this
       * ordering is not strictly required, but is still recommended.
       *
       * @param data a contiguous data buffer to send
       */
       virtual void tls_emit_data(std::span<const uint8_t> data) = 0;

       /**
       * Mandatory callback: process application data
       *
       * Called when application data record is received from the peer. Again
       * the array is overwritten immediately after the function returns.
       *
       * Currently empty records are ignored and do not instigate a callback,
       * but this may change in a future release.
       *
       * For TLS the record number will always increase. For DTLS, it is
       * possible to receive records with the @p seq_no field out of order, or
       * with gaps, corresponding to reordered or lost datagrams.
       *
       * @param seq_no the underlying TLS/DTLS record sequence number
       * @param data a contiguous data buffer containing the received record
       */
       virtual void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) = 0;

       /**
       * Mandatory callback: alert received
       *
       * Called when an alert is received from the peer. If fatal, the
       * connection is closing. If not fatal, the connection may still be
       * closing (depending on the error and the peer).
       *
       * Note that alerts received before the handshake is complete are not
       * authenticated and could have been inserted by a MITM attacker.
       *
       * @param alert the source of the alert
       */
       virtual void tls_alert(Alert alert) = 0;

       /// @}

       /**
        * @name Informational
        *
        * Override these to obtain deeper insights into the TLS connection.
        * Throwing from any of these callbacks will result in the termination of
        * the TLS connection.
        * @{
        */

       /**
       * Optional callback: session established
       *
       * Called whenever a negotiation completes. This can happen more than once
       * on TLS 1.2 connections, if renegotiation occurs. The @p session
       * parameter provides information about the session which was just
       * established.
       *
       * If this function wishes to cancel the handshake, it can throw an
       * exception which will send a close message to the counterparty and reset
       * the connection state.
       *
       * @param session the session descriptor
       */
       virtual void tls_session_established(const Session_Summary& session) { BOTAN_UNUSED(session); }

       /**
       * Optional callback: session activated
       *
       * By default does nothing. This is called when the session is activated,
       * that is once it is possible to send or receive data on the channel.  In
       * particular it is possible for an implementation of this function to
       * perform an initial write on the channel.
       */
       virtual void tls_session_activated() {}

       /**
       * Optional callback: peer closed connection (sent a "close_notify" alert)
       *
       * The peer signaled that it wishes to shut down the connection. The
       * application should not expect to receive any more data from the peer
       * and may tear down the underlying transport socket.
       *
       * Prior to TLS 1.3 it was required that peers discard pending writes
       * and immediately respond with their own "close_notify". With TLS 1.3,
       * applications can continue to send data despite the peer having already
       * signaled their wish to shut down.
       *
       * Returning `true` will cause the TLS 1.3 implementation to write all
       * pending data and then also signal a connection shut down. Otherwise
       * the application is responsible to call the `Channel::close()` method.
       *
       * For TLS 1.2 the return value has no effect.
       *
       * @return true causes the implementation to respond with a "close_notify"
       */
       virtual bool tls_peer_closed_connection()
         {
         return true;
         }

       /**
       * Optional callback: Resumption information was received/established
       *
       * TLS 1.3 calls this when we sent or received a TLS 1.3 session ticket at
       * any point after the initial handshake has finished.
       *
       * TLS 1.2 calls this when a session was established successfully and
       * its resumption information may be stored for later usage.
       *
       * Note that for servers this is called as soon as resumption information
       * is available and _could_ be sent to the client. If this callback
       * returns 'false', the information will neither be cached nor sent.
       *
       * @param session the session descriptor
       *
       * @return false to prevent the resumption information from being cached,
       *         and true to cache it in the configured Session_Manager
       */
       virtual bool tls_should_persist_resumption_information(const Session& session);

       /**
       * Optional callback: inspect handshake message
       *
       * Throw an exception to abort the handshake. Default simply ignores the
       * message.
       *
       * Note: On connections that negotiated TLS 1.3 this callback is also
       *       invoked for post-handshake messages.
       *
       * @param message the handshake message
       */
       virtual void tls_inspect_handshake_msg(const Handshake_Message& message);

       /**
       * Optional callback: examine peer extensions.
       *
       * Both client and server will call this callback with the Extensions
       * object after receiving it from the peer. This allows examining the
       * Extensions, for example to implement a custom extension. It also allows
       * an application to require that a particular extension be implemented;
       * throw an exception from this function to abort the handshake.
       *
       * Default implementation does nothing.
       *
       * @param extn the extensions
       * @param which_side will be Connection_Side::Client if these are are the clients extensions (ie we are
       *        the server) or Connection_Side::Server if these are the server extensions (we are the client).
       * @param which_message will state the handshake message type containing the extensions
       */
       virtual void tls_examine_extensions(const Extensions& extn, Connection_Side which_side, Handshake_Type which_message);

       /// @}

       /**
       * @name Providers
       *
       * Override these to customize certain aspects of the TLS implementation.
       * Applications might use this to offload asymmetric cryptographic
       * operations to custom hardware. Even the implementation of custom TLS
       * extensions is within scope to some extent.
       * @{
       */

      /**
       * Optional callback: examine/modify Extensions before sending.
       *
       * Both client and server will call this callback on the Extensions object
       * before serializing it in the specific handshake message. This allows an
       * application to modify which extensions are sent during the handshake.
       *
       * Default implementation does nothing.
       *
       * @param extn the extensions
       * @param which_side will be Connection_Side::Client or Connection_Side::Server which is the current
       *                   applications role in the exchange.
       * @param which_message will state the handshake message type containing the extensions
       */
       virtual void tls_modify_extensions(Extensions& extn, Connection_Side which_side, Handshake_Type which_message);

       /**
       * Optional callback with default impl: verify cert chain
       *
       * Default implementation performs a standard PKIX validation and
       * initiates network OCSP request for end-entity cert. Override to provide
       * different behavior; like pinning the public key.
       *
       * Check the certificate chain is valid up to a trusted root, and
       * optionally (if hostname != "") that the hostname given is consistent
       * with the leaf certificate. The first certificate in @p cert_chain is
       * assumed to be the end entity.
       *
       * If @p usage is Usage_Type::TLS_SERVER_AUTH, then @p hostname should
       * match the information in the server certificate. If usage is
       * Usage_Type::TLS_CLIENT_AUTH, then @p hostname specifies the host the
       * client is authenticating against (from SNI); the callback can use this
       * for any special site specific authentication logic.
       *
       * The @p ocsp_responses is a possibly empty list of OCSP responses
       * provided by the server. In TLS 1.2 at most the end-entity will have an
       * OCSP response stapled to it. An existing TLS extension allows the
       * server to send multiple OCSP responses, though Botan currently does not
       * implement it. For TLS 1.3 each certificate in the @p cert_chain may
       * have an associated response in the @p ocsp_responses list.
       *
       * The @p trusted_roots parameter was returned by a call from the
       * associated Credentials_Manager.
       *
       * The @p policy provided is the policy for the TLS session which is being
       * authenticated using this certificate chain. It can be consulted for
       * values such as allowable signature methods and key sizes.
       *
       * This function should throw an exception derived from std::exception
       * with an informative what() result if the certificate chain cannot be
       * verified. The TLS session establishment will be cancelled in this case.
       *
       * @param cert_chain specifies a certificate chain leading to a trusted
       *        root CA certificate.
       * @param ocsp_responses the server may have provided some
       * @param trusted_roots the list of trusted certificates
       * @param usage what this cert chain is being used for
       *        Usage_Type::TLS_SERVER_AUTH for server chains,
       *        Usage_Type::TLS_CLIENT_AUTH for client chains,
       *        Usage_Type::UNSPECIFIED for other uses
       * @param hostname when authenticating a server, this is the hostname the
       *        client requested (eg via SNI). When authenticating a client,
       *        this is the server name the client is authenticating *to*. Empty
       *        in other cases or if no hostname was used.
       * @param policy the TLS policy associated with the session being
       *        authenticated using the certificate chain
       */
       virtual void tls_verify_cert_chain(
          const std::vector<X509_Certificate>& cert_chain,
          const std::vector<std::optional<OCSP::Response>>& ocsp_responses,
          const std::vector<Certificate_Store*>& trusted_roots,
          Usage_Type usage,
          const std::string& hostname,
          const TLS::Policy& policy);

      /**
       * Called by the TLS server whenever the client included the
       * status_request extension (see RFC 6066, a.k.a OCSP stapling)
       * in the ClientHello.
       *
       * @return the encoded OCSP response to be sent to the client which
       * indicates the revocation status of the server certificate. Return an
       * empty vector to indicate that no response is available, and thus
       * suppress the Certificate_Status message.
       */
       virtual std::vector<uint8_t> tls_provide_cert_status(const std::vector<X509_Certificate>& chain,
                                                            const Certificate_Status_Request& csr)
          {
          BOTAN_UNUSED(chain);
          BOTAN_UNUSED(csr);
          return std::vector<uint8_t>();
          }

      /**
       * Called by TLS 1.3 client or server whenever the peer indicated that
       * OCSP stapling is supported. In contrast to `tls_provide_cert_status`,
       * this allows providing OCSP responses for each certificate in the chain.
       *
       * The default implementation invokes `tls_provide_cert_status` assuming
       * that no OCSP responses for intermediate certificates are available.
       *
       * @return a vector of OCSP response buffers. An empty buffer indicates
       *         that no OCSP response should be provided for the respective
       *         certificate (at the same list index). The returned vector
       *         MUST be exactly the same length as the incoming \p chain.
       */
      virtual std::vector<std::vector<uint8_t>> tls_provide_cert_chain_status(const std::vector<X509_Certificate>& chain,
                                                                              const Certificate_Status_Request& csr);

       /**
       * Optional callback with default impl: sign a message
       *
       * Default implementation uses PK_Signer::sign_message().
       * Override to provide a different approach, e.g. using an external device.
       *
       * @param key the private key of the signer
       * @param rng a random number generator
       * @param emsa the encoding method to be applied to the message
       * @param format the signature format
       * @param msg the input data for the signature
       *
       * @return the signature
       */
       virtual std::vector<uint8_t> tls_sign_message(
          const Private_Key& key,
          RandomNumberGenerator& rng,
          const std::string& emsa,
          Signature_Format format,
          const std::vector<uint8_t>& msg);

       /**
       * Optional callback with default impl: verify a message signature
       *
       * Default implementation uses PK_Verifier::verify_message().
       * Override to provide a different approach, e.g. using an external device.
       *
       * @param key the public key of the signer
       * @param emsa the encoding method to be applied to the message
       * @param format the signature format
       * @param msg the input data for the signature
       * @param sig the signature to be checked
       *
       * @return true if the signature is valid, false otherwise
       */
       virtual bool tls_verify_message(
          const Public_Key& key,
          const std::string& emsa,
          Signature_Format format,
          const std::vector<uint8_t>& msg,
          const std::vector<uint8_t>& sig);

      /**
       * Generate an ephemeral key pair for the TLS handshake.
       *
       * Applications may use this to add custom groups, curves or entirely
       * different ephemeral key agreement mechanisms to the TLS handshake.
       * Note that this callback must be used in conjunction with
       * Callbacks::tls_ephemeral_key_agreement.
       *
       * Typical use cases of the library don't need to do that and serious
       * security risks are associated with customizing TLS's key exchange
       * mechanism.
       *
       * @throws TLS_Exception(Alert::DecodeError) if the @p group is not known.
       *
       * @param group the group identifier to generate an ephemeral keypair for
       *              TLS 1.2 allows for specifying custom discrete logarithm
       *              parameters as part of the protocol. Hence the variant<>.
       * @param rng a random number generator
       *
       * @return a private key of an algorithm usable for key agreement
       */
      virtual std::unique_ptr<PK_Key_Agreement_Key> tls_generate_ephemeral_key(
         const std::variant<TLS::Group_Params, DL_Group>& group,
         RandomNumberGenerator& rng);

      /**
       * Agree on a shared secret with the peer's ephemeral public key for
       * the TLS handshake.
       *
       * Applications may use this to add custom groups, curves or entirely
       * different ephemeral key agreement mechanisms to the TLS handshake.
       * Note that this callback must be used in conjunction with
       * Callbacks::tls_generate_ephemeral_key.
       *
       * Typical use cases of the library don't need to do that and serious
       * security risks are associated with customizing TLS's key exchange
       * mechanism.
       *
       * @param group         the TLS group identifier to be used
       *                      TLS 1.2 allows for specifying custom discrete
       *                      logarithm parameters as part of the protocol.
       *                      Hence the variant<>.
       * @param private_key   the private key (generated ahead in tls_generate_ephemeral_key)
       * @param public_value  the public key exchange information received by the peer
       * @param rng           a random number generator
       * @param policy        a TLS policy object
       *
       * @return the shared secret derived from public_value and private_key
       */
      virtual secure_vector<uint8_t> tls_ephemeral_key_agreement(
         const std::variant<TLS::Group_Params, DL_Group>& group,
         const PK_Key_Agreement_Key& private_key,
         const std::vector<uint8_t>& public_value,
         RandomNumberGenerator& rng,
         const Policy& policy);

       /**
       * Optional callback for server: choose ALPN protocol
       *
       * ALPN (RFC 7301) works by the client sending a list of application
       * protocols it is willing to negotiate. The server then selects which
       * protocol to use. RFC 7301 requires that if the server does not support
       * any protocols offered by the client, then it should close the
       * connection with an alert of no_application_protocol. Within this
       * callback this would be done by throwing a
       * TLS_Exception(Alert::NoApplicationProtocol).
       *
       * The default implementation returns the empty string, causing client
       * ALPN to be ignored.
       *
       * It is highly recommended to support ALPN whenever possible to avoid
       * cross-protocol attacks.
       *
       * @warning The ALPN RFC requires that if the server does not understand
       *          any of the protocols offered by the client, it should close
       *          the connection using an alert. Carrying on the connection (for
       *          example by ignoring ALPN when the server does not understand
       *          the protocol list) can expose applications to cross-protocol
       *          attacks.
       *
       * @param client_protos the vector of protocols the client is willing to
       *                      negotiate
       *
       * @return the protocol selected by the server; if the empty string is
       *         returned, the server does not reply to the client ALPN
       *         extension.
       */
       virtual std::string tls_server_choose_app_protocol(const std::vector<std::string>& client_protos);

       /// @}

       /**
        * @name Configuration
        *
        * Customization point for certain configurations or test mocking helpers.
        * @{
        */

       /**
       * Called by default tls_verify_cert_chain() to get the timeout to use for
       * OCSP requests. Return 0 to disable online OCSP checks.
       */
       virtual std::chrono::milliseconds tls_verify_cert_chain_ocsp_timeout()
          {
          return std::chrono::milliseconds(0);
          }

       /**
       * Optional callback: return peer network identity
       *
       * There is no expected or specified format. The only expectation is this
       * function will return a unique value. For example returning the peer
       * host IP and port.
       *
       * This is used to bind the DTLS cookie to a particular network identity.
       * It is only called if the dtls-cookie-secret PSK is also defined.
       */
       virtual std::string tls_peer_network_identity();

      /**
       * Optional callback: parse a single OCSP Response
       *
       * Note: Typically a user of the library would not want to override this
       *       callback. We provide this callback to be able to support OCSP
       *       related tests from BoringSSL's BoGo tests that provide unparsable
       *       responses.
       *
       * Default implementation tries to parse the provided raw OCSP response.
       *
       * This function should not throw an exception but return a std::nullopt
       * if the OCSP response cannot be parsed.
       *
       * @param raw_response raw OCSP response buffer
       * @returns the parsed OCSP response or std::nullopt on error
       */
       virtual std::optional<OCSP::Response> tls_parse_ocsp_response(const std::vector<uint8_t>& raw_response);

       /**
       * Optional callback: return a custom time stamp value
       *
       * This allows the library user to specify a custom "now" timestamp when
       * needed. By default it will use the current system clock time.
       *
       * Note that typical usages will not need to override this callback but it
       * is useful for testing purposes to allow for deterministic test outcomes.
       */
       virtual std::chrono::system_clock::time_point tls_current_timestamp();

       /// @}

       /**
        * @name Logging
        *
        * Taps for logging. Currently unused.
        * @{
        */

       /**
       * Optional callback: error logging. (not currently called)
       * @param err An error message related to this connection.
       */
       virtual void tls_log_error(const char* err)
          {
          BOTAN_UNUSED(err);
          }

       /**
       * Optional callback: debug logging. (not currently called)
       * @param what Some hopefully informative string
       */
       virtual void tls_log_debug(const char* what)
          {
          BOTAN_UNUSED(what);
          }

       /**
       * Optional callback: debug logging taking a buffer. (not currently called)
       * @param descr What this buffer is
       * @param val the bytes
       * @param val_len length of val
       */
       virtual void tls_log_debug_bin(const char* descr, const uint8_t val[], size_t val_len)
          {
          BOTAN_UNUSED(descr, val, val_len);
          }

       /// @}
   };

}

}

#endif
