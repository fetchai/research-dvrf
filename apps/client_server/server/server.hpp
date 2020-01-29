#pragma once
//------------------------------------------------------------------------------
//
//   Copyright 2019-2020 Fetch.AI Limited
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
//------------------------------------------------------------------------------

#include "ecdsa.hpp"
#include "network.hpp"
#include "messages.hpp"
#include "logger.hpp"
#include "consensus.pb.h"
#include <iostream>

namespace fetch {
namespace consensus {

/**
 * Node which uses network connections specified by ip address
 *
 * @tparam CryptoType Crypto type in DKG
 */
class Server {
  using ECDSASignature = ECDSAKey::ECDSASignature;

  struct Connection {
    tcp::socket socket_;
    std::string name_;
    std::string ip_;
    uint16_t port_;
    std::string publicKey_;
    std::pair<std::vector<uint8_t>, ECDSASignature> signedDHPublicKey_;
    std::atomic<bool> stopped_{false};
    std::mutex mutex_;

    explicit Connection(tcp::socket socket) : socket_{std::move(socket)} {}

    ~Connection() {
      disconnect();
    }

    void disconnect() {
      std::lock_guard<std::mutex> lock(mutex_);
      stopped_ = true;
      if (socket_.is_open()) {
        socket_.close();
        try {
          socket_.shutdown(asio::socket_base::shutdown_both);
        } catch (const asio::system_error &) {}
      }
    }
  };

  asio::io_context &io_context_;
  const uint16_t port_; // > 1023
  const std::string ip_;
  std::unique_ptr<tcp::acceptor> acceptor_;
  std::mutex connection_mutex_;
  std::unordered_map<std::string, std::shared_ptr<Connection>> connections_;
  static fetch::consensus::Logger logger;

  void addConnection(std::shared_ptr<Connection> connection) {
    logger.info("AddConnection to {}", connection->name_);
    std::lock_guard<std::mutex> lock(connection_mutex_);
    auto iter = connections_.find(connection->name_);
    if (iter != connections_.end()) {
      return;
    }

    // Add new connection
    connections_.insert({connection->name_, connection});

    // Broadcast to existing connections about new connection
    Neighbour msg{connection->name_, connection->port_, connection->publicKey_, connection->signedDHPublicKey_};
    std::vector<Neighbour> existing_connections;
    auto buffer = serialize(msg.handle());
    for (auto &con : connections_) {
      if (con.first != connection->name_) {
        std::error_code error_code = writeBuffer(con.second->socket_, buffer);
        if (error_code) {
          logger.error("Sever failed to send msg to {}", con.first);
        }
        existing_connections.emplace_back(con.second->name_, con.second->port_, con.second->publicKey_,
                                          con.second->signedDHPublicKey_);
      }
    }

    // Send connection all existing connections
    for (const auto &con_msg : existing_connections) {
      auto msg_buffer = serialize(con_msg.handle());
      std::error_code error_code = writeBuffer(connection->socket_, msg_buffer);
      if (error_code) {
        logger.error("Sever failed to send msg to {}", connection->name_);
      }
    }
  }

  void newNeighbour(tcp::socket socket) {
    auto ip = socket.remote_endpoint().address().to_string();
    logger.trace("newNeighbour {}", ip);
    auto connection = std::make_shared<Connection>(std::move(socket));
    asyncReadBuffer(connection->socket_, 5,
                    [this, connection](std::error_code ec, std::shared_ptr<Buffer> buffer) {
                      if (ec) {
                        logger.error("newNeighbour read failure {}", ec.value());
                      } else {
                        auto n = deserialize<fetch::consensus::pb::Neighbour>(*buffer);
                        connection->ip_ = connection->socket_.remote_endpoint().address().to_string();
                        connection->name_ = n.id();
                        connection->port_ = n.port();
                        connection->publicKey_ = n.public_key();
                        std::vector<uint8_t> dhPublicKey;
                        for (uint16_t i = 0; i < n.dh_public_key_size(); ++i) {
                          dhPublicKey.push_back(static_cast<uint8_t>(n.dh_public_key(i)));
                        }
                        ECDSASignature signature;
                        for (uint16_t i = 0; i < n.key_signature_size(); ++i) {
                          signature.push_back(static_cast<uint8_t>(n.key_signature(i)));
                        }
                        connection->signedDHPublicKey_ = std::make_pair(dhPublicKey, signature);
                        addConnection(connection);
                      }
                    });
  }

  void accept() {
    logger.trace("accept");
    acceptor_->async_accept([this](std::error_code ec, tcp::socket socket) {
      if (!ec) {
        logger.trace("new neighbour");
        newNeighbour(std::move(socket));
        accept();
      } else {
        if (ec == asio::error::operation_aborted) {
          logger.debug("accept aborted {}", ec.value());
        } else {
          logger.error("accept error {} msg {}", ec.value(), ec.message());
        }
      }
    });
  }

  void disconnect() {
    if (acceptor_) {
      acceptor_->close();
    }
    std::lock_guard<std::mutex> lock(connection_mutex_);
    for (auto &c : connections_) {
      c.second->disconnect();
    }
  }

public:
  explicit Server(asio::io_context &io_context, uint16_t port,
                  std::string ip = "127.0.0.1") : io_context_{io_context}, port_{port}, ip_{std::move(ip)} {
    std::unordered_set<std::string> local_ips = {"localhost", "127.0.0.1"};
    tcp::resolver resolver(io_context_);
    std::string h = asio::ip::host_name();
    for (auto &re : resolver.resolve({h, ""})) {
      local_ips.insert(re.endpoint().address().to_string());
    }
    if (local_ips.find(ip_) != local_ips.end()) {
      // local ip
      acceptor_ = std::unique_ptr<tcp::acceptor>(new tcp::acceptor(io_context_, tcp::endpoint(tcp::v4(), port_)));
      acceptor_->listen();
      accept();
    }
  }

  const std::string ip() const { return ip_; }

  uint16_t port() const { return port_; }

  virtual ~Server() {
    disconnect();
  }
};

Logger Server::logger = fetch::consensus::Logger("server");
}
};
