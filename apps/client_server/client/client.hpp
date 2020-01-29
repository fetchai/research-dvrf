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
#include "networknode.hpp"
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
template<class Drb>
class Client : public NetworkNode<Drb> {
  using ECDSASignature = ECDSAKey::ECDSASignature;
  static fetch::consensus::Logger logger;

  struct ServerConnection {
    Client &node_;
    tcp::socket socket_;
    uint16_t port_;
    std::atomic<bool> stopped_{false};
    std::mutex mutex_;

    explicit ServerConnection(Client &node, tcp::socket socket) : node_{node}, socket_{std::move(socket)} {}

    void read() {
      asyncReadBuffer(socket_, 5, [this](std::error_code ec, std::shared_ptr<Buffer> buffer) {
        if (ec) {
          if (ec == asio::error::operation_aborted || ec == asio::error::eof) {
            logger.debug("ServerConnection::read aborted on ec {}", ec.value());
          } else {
            logger.error("ServerConnection::read error on ec {} msg {}", ec.value(),
                         ec.message());
          }
        } else {
          logger.trace("ServerConnection::read successful");
          process(buffer);
          if (!stopped_) {
            read();
          }
        }
      });
    }

    ~ServerConnection() {
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

    void process(const std::shared_ptr<Buffer> &buffer) {
      if (stopped_) {
        return;
      }
      auto msg = deserialize<fetch::consensus::pb::Neighbour>(*buffer);
      std::vector<uint8_t> dhPublicKey;
      for (uint16_t i = 0; i < msg.dh_public_key_size(); ++i) {
        dhPublicKey.push_back(static_cast<uint8_t>(msg.dh_public_key(i)));
      }
      ECDSASignature signature;
      for (uint16_t i = 0; i < msg.key_signature_size(); ++i) {
        signature.push_back(static_cast<uint8_t>(msg.key_signature(i)));
      }
      node_.addConnection(msg.id(), msg.port(), msg.public_key(),
                          std::make_pair(dhPublicKey, signature));
    }
  };

  std::shared_ptr<ServerConnection> server_;
  std::mutex committee_mutex_;
  std::vector<std::unique_ptr<NetworkNode<Drb>>> neighbourNodes_;
  std::set<std::string> committee_;
  uint32_t committee_size_{0};
  uint32_t threshold_{0};

public:
  /**
   * Constructs a genuine network node which can send and receive messages
   * @param name Node name
   * @param eventObserver Local observer for logging events
   * @param io_context Context
   * @param port Port number
   * @param ip IP address
   */
  explicit Client(std::string name, EventObserver &eventObserver, asio::io_context &io_context, uint16_t port,
                  uint32_t committee_size, uint32_t threshold,
                  std::string ip = "127.0.0.1")
          : NetworkNode<Drb>{name, eventObserver, io_context, port, std::move(ip)},
            committee_size_{committee_size}, threshold_{threshold} {
    logger.trace("Client port {} ip {}", port, this->ip_);
    committee_.insert(name);
  }

  virtual ~Client() {
    logger.trace("~Client port {} ip {}", this->port_, this->ip_);
    disconnect();
  }

  void disconnect() {
    logger.trace("disconnect port {} ip {}", this->port_, this->ip_);
    std::lock_guard<std::mutex> lock(this->connection_mutex_);
    server_->disconnect();
  }

  void connectServer(std::string const &ip, uint16_t port) {
    tcp::resolver resolver{this->io_context_};
    logger.trace("connect to server port {}", port);
    std::error_code ec;
    tcp::endpoint ep{asio::ip::address::from_string(ip), port};
    int tries = 3;
    tcp::socket socket{this->io_context_, ep.protocol()};
    do {
      --tries;
      socket.connect(ep, ec);
      if (ec) {
        logger.error("server connection error ip {} port {} error {}", ip, port, ec.value());
        std::this_thread::sleep_for(std::chrono::seconds{1});
      } else {
        Neighbour msg{this->id_, this->port_, this->ECDSAPublicKey(), this->signedDHPublicKey()};
        auto buffer = serialize(msg.handle());
        std::error_code error_code = writeBuffer(socket, buffer);
        if (error_code) {
          logger.error("connect from {} failed to send msg to server",
                       this->id_);
        } else {
          server_ = std::make_shared<ServerConnection>(*this, std::move(socket));
          server_->read();
        }
      }
    } while (tries > 0 && ec);
    if (ec) {
      logger.error("server connection error ip {} port {} error {}", ip, port, ec.value());
    }
  }

  void addConnection(std::string const &id, uint16_t port, const std::string &publicKey,
                     const std::pair<std::vector<uint8_t>, ECDSASignature> &signedDHPublicKey) {
    assert(this->id_ != id);
    logger.debug("{} add new connection {} port {}", this->id_, id, port);
    neighbourNodes_.emplace_back(new NetworkNode<Drb>{id, this->eventObserver_, this->io_context_, port, publicKey,
                                                      signedDHPublicKey});
    if (neighbourNodes_.back()->id() != this->id_ and this->neighbourhood_.updateNeighbour(*neighbourNodes_.back())) {
      if (!this->known(*neighbourNodes_.back())) {
        this->connect(*neighbourNodes_.back());
      }
    }
    receivedConnection(neighbourNodes_.back()->id());
  }

  void receivedConnection(const std::string &id) {
    std::lock_guard<std::mutex> lock(committee_mutex_);
    committee_.insert(id);
    if (this->connections_.size() == committee_size_ - 1) {
      logger.info("{} connected to all committee members", this->id_);
      this->committeeManager_ = std::unique_ptr<CommitteeManager<Drb>>(
              new CommitteeManager<Drb>{committee_, *this, threshold_});
      this->getEventObserver().notifyNewConnection("", "");
    }
  }
};

template<class Drb>
Logger Client<Drb>::logger = fetch::consensus::Logger("client");
}
};
