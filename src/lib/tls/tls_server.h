/*
* TLS Server
* (C) 2004-2011 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_SERVER_H_
#define BOTAN_TLS_SERVER_H_

#include <botan/tls_channel.h>
#include <botan/tls_policy.h>
#include <botan/credentials_manager.h>
#include <vector>

namespace Botan {

namespace TLS {

class Channel_Impl;

/**
* TLS Server
*/
class BOTAN_PUBLIC_API(2,0) Server final : public Channel
   {
   public:
      /**
      * Server initialization
      *
      * The first 5 arguments as well as the final argument
      * @p reserved_io_buffer_size, are treated similarly to the TLS::Client().
      *
      * If a client sends the ALPN extension, the
      * TLS::Callbacks::tls_server_choose_app_protocol() will be called and the
      * result sent back to the client. If the empty string is returned, the
      * server will not send an ALPN response. The function can also throw an
      * exception to abort the handshake entirely, the ALPN specification says
      * that if this occurs the alert should be of type
      * TLS::AlertType::NoApplicationProtocol.
      *
      * The optional argument @p is_datagram specifies if this is a TLS or DTLS
      * server; unlike clients, which know what type of protocol (TLS vs DTLS)
      * they are negotiating from the start via the @p offer_version, servers
      * would not until they actually received a client hello.
      *
      * @param callbacks contains a set of callback function references required
      *        by the TLS server.
      *
      * @param session_manager manages session state
      *
      * @param creds manages application/user credentials
      *
      * @param policy specifies other connection policy information
      *
      * @param rng a random number generator
      *
      * @param is_datagram set to true if this server should expect DTLS
      *        connections. Otherwise TLS connections are expected.
      *
      * @param reserved_io_buffer_size This many bytes of memory will be
      *        preallocated for the read and write buffers. Smaller values just
      *        mean reallocations and copies are more likely.
      */
      Server(const std::shared_ptr<Callbacks>& callbacks,
             const std::shared_ptr<Session_Manager>& session_manager,
             const std::shared_ptr<Credentials_Manager>& creds,
             const std::shared_ptr<const Policy>& policy,
             const std::shared_ptr<RandomNumberGenerator>& rng,
             bool is_datagram = false,
             size_t reserved_io_buffer_size = TLS::Channel::IO_BUF_DEFAULT_SIZE
         );

      ~Server();

      /**
      * Return the protocol notification set by the client (using the
      * ALPN extension) for this connection, if any. This value is not
      * tied to the session and a later renegotiation of the same
      * session can choose a new protocol.
      */
      std::string application_protocol() const override;

      size_t from_peer(std::span<const uint8_t> data) override;

      bool is_active() const override;

      bool is_closed() const override;

      bool is_closed_for_reading() const override;
      bool is_closed_for_writing() const override;

      std::vector<X509_Certificate> peer_cert_chain() const override;

      SymmetricKey key_material_export(const std::string& label,
                                       const std::string& context,
                                       size_t length) const override;

      void renegotiate(bool force_full_renegotiation = false) override;

      bool new_session_ticket_supported() const;
      size_t send_new_session_tickets(const size_t tickets = 1);

      void update_traffic_keys(bool request_peer_update = false) override;

      bool secure_renegotiation_supported() const override;

      void to_peer(std::span<const uint8_t> data) override;

      void send_alert(const Alert& alert) override;

      void send_warning_alert(Alert::Type type) override;

      void send_fatal_alert(Alert::Type type) override;

      void close() override;

      bool timeout_check() override;

   private:
      std::unique_ptr<Channel_Impl> m_impl;
   };
}

}

#endif
