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

#include "node_impl.hpp"
#include "network.hpp"
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
template<class CryptoType>
class NetworkNode : public Node<CryptoType, NetworkNode<CryptoType>> {
  using ECDSASignature = ECDSAKey::ECDSASignature;

protected:
  struct Connection {
    NetworkNode &node_;
    tcp::socket socket_;
    bool accepted_;
    std::string name_;
    std::string ip_;
    uint16_t port_;
    std::string publicKey_;
    std::pair<std::vector<uint8_t>, ECDSASignature> signedDHPublicKey_;
    std::atomic<bool> stopped_{false};
    std::mutex mutex_;

    std::unique_ptr<NetworkNode> memory_;

    explicit Connection(NetworkNode &node, tcp::socket socket, bool accepted) :
            node_{node}, socket_{std::move(socket)}, accepted_{accepted} {}

    void read() {
      asyncReadBuffer(socket_, 5, [this](std::error_code ec, std::shared_ptr<Buffer> buffer) {
        if (ec) {
          if (ec == asio::error::operation_aborted || ec == asio::error::eof) {
            logger.debug("Connection::read aborted on id {} from {} ec {}", name_, node_.id(), ec.value());
          } else {
            logger.error("Connection::read error on id {} from {} ec {} msg {}", name_, node_.id(), ec.value(),
                         ec.message());
          }
        } else {
          logger.trace("Connection::read successful on id {} from {}", name_, node_.id());
          process(buffer);
          if (!stopped_) {
            read();
          }
        }
      });
    }

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

    void processJoin(const fetch::consensus::pb::Message_Join &join) {
      logger.trace("connection {} received join from {}", node_.id(), name_);
      std::set<std::string> newNodes;
      for (auto &n : join.nodes()) {
        newNodes.insert(n);
      }
      NetworkNode *node = node_.getNeighbour(name_);
      if (!node) {
        memory_ = std::unique_ptr<NetworkNode>(
                new NetworkNode(name_, node_.getEventObserver(), socket_.get_io_context(), port_, publicKey_,
                                signedDHPublicKey_, ip_));
        node = memory_.get();
      }
      node_.onJoin(newNodes, *node);
    }

    void processGossip(const fetch::consensus::pb::Message_Gossip &gossip) {
      logger.trace("connection {} received gossip from {}", node_.id(), name_);
      NetworkNode *node = node_.getNeighbour(name_);
      if (!node) {
        memory_ = std::unique_ptr<NetworkNode>(
                new NetworkNode(name_, node_.getEventObserver(), socket_.get_io_context(), port_, publicKey_,
                                signedDHPublicKey_, ip_));
        node = memory_.get();
      }
      std::vector<uint8_t> signature;
      for (auto i = 0; i < gossip.signature_size(); ++i) {
        signature.push_back(static_cast<uint8_t>(gossip.signature(i)));
      }
      node_.onGossip(gossip.step(), gossip.gossip(), gossip.msg(), signature, gossip.origin(), *node);
    }

    void process(const std::shared_ptr<Buffer> &buffer) {
      if (stopped_)
        return;
      auto msg = deserialize<fetch::consensus::pb::Message>(*buffer);
      auto payload_case = msg.payload_case();
      switch (payload_case) {
        case fetch::consensus::pb::Message::kJoin:
          processJoin(msg.join());
          break;
        case fetch::consensus::pb::Message::kGossip:
          processGossip(msg.gossip());
          break;
        case fetch::consensus::pb::Message::PAYLOAD_NOT_SET:
          logger.error("Connection::process cannot process payload {} from {}", payload_case, name_);
      }
    }
  };

  asio::io_context &io_context_;
  const uint16_t port_; // > 1023
  const std::string ip_;
  const bool proxy_;
  std::unique_ptr<tcp::acceptor> acceptor_;
  std::mutex connection_mutex_;
  std::unordered_map<std::string, std::shared_ptr<Connection>> connections_;
  static fetch::consensus::Logger logger;

  bool known(const NetworkNode &destination) {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    return connections_.find(destination.id()) != connections_.end();
  }

  void addConnection(std::shared_ptr<Connection> connection) {
    logger.trace("AddConnection {} to {}", this->id_, connection->name_);
    std::lock_guard<std::mutex> lock(connection_mutex_);
    auto iter = connections_.find(connection->name_);
    if (iter == connections_.end()) {
      connections_.insert({connection->name_, connection});
      connection->read();
      logger.trace("AddConnection read {} from {}", this->id_, connection->name_);
    } else {
      if (iter->second->accepted_ == connection->accepted_) {
        logger.warn("AddConnection received duplicate request from same source, accepted {}", connection->accepted_);
        return;
      }
      // here there are 2 connections live.
      // we keep the one going from the lowest id to highest id where lowest id is not accepted (ie. connected).
      assert(connection->name_ == iter->second->name_);
      logger.warn("AddConnection duplicate connection {} to {}", this->id_, connection->name_);
      if (connection->name_ < this->id_) {
        if (iter->second->accepted_) {
          connection->disconnect();
          assert(!connection->accepted_);
          logger.warn("AddConnection1 dismissed {} from {} accepted {}", this->id_, connection->name_,
                      connection->accepted_);
        } else {
          iter->second->disconnect();
          assert(connection->accepted_);
          logger.warn("AddConnection2 dismissed {} from {} accepted {}", this->id_, iter->second->name_,
                      iter->second->accepted_);
          connections_[connection->name_] = connection;
          connection->read();
        }
      } else {
        if (!iter->second->accepted_) {
          connection->disconnect();
          assert(connection->accepted_);
          logger.trace("AddConnection3 dismissed {} from {} accepted {}", this->id_, connection->name_,
                       connection->accepted_);
        } else {
          iter->second->disconnect();
          assert(!connection->accepted_);
          logger.warn("AddConnection4 dismissed {} from {} accepted {}", this->id_, iter->second->name_,
                      iter->second->accepted_);
          connections_[connection->name_] = connection;
          connection->read();
        }
      }
    }
  }

  void newNeighbour(tcp::socket socket) {
    auto ip = socket.remote_endpoint().address().to_string();
    logger.trace("newNeighbour {}", ip);
    auto connection = std::make_shared<Connection>(*this, std::move(socket), true);
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
    logger.trace("accept {}", this->id_);
    acceptor_->async_accept([this](std::error_code ec, tcp::socket socket) {
      if (!ec) {
        logger.trace("{} new neighbour", this->id_);
        newNeighbour(std::move(socket));
        accept();
      } else {
        if (ec == asio::error::operation_aborted) {
          logger.debug("accept {} aborted {}", this->id_, ec.value());
        } else {
          logger.error("accept {} error {} msg {}", this->id_, ec.value(), ec.message());
        }
      }
    });
  }

  void connect(const NetworkNode &neighbour) {
    tcp::resolver resolver{io_context_};
    logger.trace("connect from {} to {}", this->id_, neighbour.id());
    std::error_code ec;
    tcp::endpoint ep{asio::ip::address::from_string(neighbour.ip()), neighbour.port()};
    int tries = 3;
    tcp::socket socket{io_context_, ep.protocol()};
    do {
      --tries;
      socket.connect(ep, ec);
      if (ec) {
        logger.error("connection error from {} to {} ip {} port {} error {}", this->id_,
                     neighbour.id(), neighbour.ip(), neighbour.port(),
                     ec);
        std::this_thread::sleep_for(std::chrono::seconds{1});
      } else {
        Neighbour msg{this->id_, port_, this->ECDSAPublicKey(), this->signedDHPublicKey()};

        auto connection = std::make_shared<Connection>(*this, std::move(socket), false);
        connection->name_ = neighbour.id();
        connection->ip_ = neighbour.ip();
        connection->port_ = neighbour.port();
        connection->publicKey_ = neighbour.ECDSAPublicKey();
        connection->signedDHPublicKey_ = neighbour.signedDHPublicKey();
        auto buffer = serialize(msg.handle());
        const std::string neighbourName = neighbour.id();
        std::error_code error_code = writeBuffer(connection->socket_, buffer);
        if (error_code) {
          logger.error("connect from {} failed to send msg to {}",
                       this->id_, neighbourName);
        } else {
          addConnection(connection);
        }
      }
    } while (tries > 0 && ec);
    if (ec)
      logger.error("connection error from {} to {} ip {} port {} error {}", this->id_,
                   neighbour.id(), neighbour.ip(), neighbour.port(),
                   ec.value());
  }

public:
  /**
   * Constructs a genuine network node which can send and receive messages
   * @param name Node name
   * @param eventObserver Local observer for logging events
   * @param io_context Context
   * @param port Port number
   * @param ip IP address
   */
  explicit NetworkNode(std::string name, EventObserver &eventObserver, asio::io_context &io_context, uint16_t port,
                       std::string ip = "127.0.0.1") :
          Node<CryptoType, NetworkNode>{std::move(name), eventObserver}, io_context_{io_context}, port_{port},
          ip_{std::move(ip)}, proxy_{false} {
    std::unordered_set<std::string> local_ips = {"localhost", "127.0.0.1"};
    logger.trace("NetworkNode {} port {} ip {} proxy {}", this->id_, port, ip_, proxy_);
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

  /**
   * Constructs a local copy of a genuine network node for processing of messages from that node
   * @param name Node name
   * @param eventObserver Local observer for logging events
   * @param io_context Context
   * @param port Port number
   * @param publicKey ECDSA public key
   * @param ip IP address
   */
  explicit NetworkNode(std::string name, EventObserver &eventObserver, asio::io_context &io_context, uint16_t port,
                       const std::string &publicKey,
                       const std::pair<std::vector<uint8_t>, ECDSASignature> signedDHPublicKey,
                       std::string ip = "127.0.0.1") :
          Node<CryptoType, NetworkNode>{std::move(name), eventObserver}, io_context_{io_context}, port_{port},
          ip_{std::move(ip)}, proxy_{true} {
    logger.trace("NetworkNode {} port {} ip {} proxy {}", this->id_, port, ip_, proxy_);
    this->ecdsaKey_.setPublicKey(publicKey);
    this->signedDHKey_ = signedDHPublicKey;
  }

  NetworkNode *getNeighbour(const std::string &node) const {
    return this->neighbourhood_.getNeighbour(node);
  }

  const std::string ip() const { return ip_; }

  uint16_t port() const { return port_; }

  virtual ~NetworkNode() {
    logger.trace("~NetworkNode {} port {} ip {} proxy {}", this->id_, port_, ip_, proxy_);
    disconnect();
  }

  void disconnect() {
    logger.trace("disconnect {} port {} ip {} proxy {}", this->id_, port_, ip_, proxy_);
    if (acceptor_)
      acceptor_->close();
    std::lock_guard<std::mutex> lock(connection_mutex_);
    for (auto &c : connections_) {
      c.second->disconnect();
    }
  }

  void join(const std::set<std::string> &newNodes, const NetworkNode &destination) {
    if (!known(destination)) {
      connect(destination);
    }
    std::lock_guard<std::mutex> lock(connection_mutex_);
    fetch::consensus::pb::Message msg;
    auto *join = msg.mutable_join();
    for (const auto &n : newNodes)
      join->add_nodes(n);
    auto buffer = serialize(msg);
    auto iter = connections_.find(destination.id());
    if (iter != connections_.end()) {
      asyncWriteBuffer(iter->second->socket_, buffer, 5);
      logger.trace("join {} from {} to {}", t_to_string(newNodes), this->id_, destination.id());
    } else {
      logger.error("error join {} from {} to {} unknown neighbour", t_to_string(newNodes), this->id_, destination.id());
    }
  }

  void
  join(const std::set<std::string> &newNodes, const std::vector<std::reference_wrapper<NetworkNode>> &destinations) {
    for (auto &destination : destinations) {
      if (!known(destination.get())) {
        connect(destination.get());
      }
    }
    std::lock_guard<std::mutex> lock(connection_mutex_);
    fetch::consensus::pb::Message msg;
    auto *join = msg.mutable_join();
    for (const auto &n : newNodes)
      join->add_nodes(n);
    auto buffer = serialize(msg);
    for (auto &destination : destinations) {
      auto iter = connections_.find(destination.get().id());
      if (iter != connections_.end()) {
        asyncWriteBuffer(iter->second->socket_, buffer, 5);
        logger.trace("join {} from {} to {}", t_to_string(newNodes), this->id_, destination.get().id());
      } else {
        logger.error("error join {} from {} to {} unknown neighbour", t_to_string(newNodes), this->id_,
                     destination.get().id());
      }
    }
  }

  void gossip(uint64_t step, bool is_gossip, const std::string &msg, const ECDSASignature &signature,
              const std::string &emitter,
              const NetworkNode &destination) {
    if (!known(destination)) {
      logger.info("{} unknown destination {}. Connecting", destination.id());
      connect(destination);
    }
    std::lock_guard<std::mutex> lock(connection_mutex_);
    fetch::consensus::pb::Message msg_pb;
    auto *gossip = msg_pb.mutable_gossip();
    gossip->set_step(step);
    gossip->set_gossip(is_gossip);
    gossip->set_msg(msg);
    gossip->set_origin(emitter);
    for (uint32_t i = 0; i < signature.size(); ++i) {
      gossip->add_signature(signature[i]);
    }
    auto buffer = serialize(msg_pb);
    auto iter = connections_.find(destination.id());
    if (iter != connections_.end()) {
      asyncWriteBuffer(iter->second->socket_, buffer, 5);
      logger.trace("gossip from {} to {}", this->id_, destination.id());
    } else {
      logger.error("error gossip from {} to {} unknown neighbour", this->id_, destination.id());
    }
  }

  void addAllNeighbours(const std::vector<std::unique_ptr<NetworkNode>> &all_nodes, uint32_t threshold) {
    std::set<std::string> committee;
    for (const auto &node : all_nodes) {
      if (node->id() != this->id_ and this->neighbourhood_.updateNeighbour(*node)) {
        if (!known(*node)) {
          connect(*node);
        }
      }
      committee.insert(node->id());
    }
    this->committeeManager_ = std::unique_ptr<CommitteeManager<CryptoType>>(
            new CommitteeManager<CryptoType>{committee, *this, threshold});
  }
};

template<class CryptoType>
Logger NetworkNode<CryptoType>::logger = fetch::consensus::Logger("network-node");
}
};
