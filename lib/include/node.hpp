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

extern "C" {
#include <noise/protocol.h>
};

#include "consensus.pb.h"
#include "event_observer.hpp"
#include "ecdsa.hpp"
#include "logger.hpp"
#include "messages.hpp"

#include <functional>
#include <memory>
#include <numeric>
#include <queue>
#include <unordered_set>
#include <unordered_map>
#include <random>

#define MAX_MESSAGE_LEN 4096

template<typename T>
const std::string t_to_string(const T &ts) {
  std::string res = "[ ";
  for (auto &t : ts) {
    res += t + " ";
  }
  res += "]";
  return res;
}

namespace fetch {
namespace consensus {
template<class CryptoType>
class CommitteeManager;

class AbstractNode {
protected:
  const std::string id_; // must be unique in the graph
  EventObserver &eventObserver_;

  AbstractNode(std::string id, EventObserver &eventObserver) : id_{std::move(id)}, eventObserver_{eventObserver} {}

public:
  using GossipKey = uint32_t;
  using ECDSASignature = ECDSAKey::ECDSASignature;

  EventObserver &getEventObserver() { return eventObserver_; }

  virtual ~AbstractNode() = default;

  std::size_t hash() const {
    return std::hash<std::string>{}(id_);
  }

  bool operator==(const AbstractNode &other) const {
    return id_ == other.id_;
  }

  bool operator!=(const AbstractNode &other) const {
    return id_ != other.id_;
  }

  const std::string id() const { return id_; }

  virtual std::size_t networkSize() const = 0;
  virtual uint32_t networkIndex() const = 0;
  virtual void sendGossip(const Gossip &message, GossipKey gossipKey = 0) = 0;
  virtual void sendDirect(const fetch::consensus::pb::Direct &msg, const std::string &peerId = "") = 0;
  virtual void onBroadcast(const std::string &message, std::string from) = 0;
  virtual void onJoin(const std::set<std::string> &newNodes, AbstractNode &from) = 0;
  virtual void
  onGossip(GossipKey gossipKey, bool broadcast, const std::string &message, const ECDSASignature &signature,
           const std::string &emitter,
           AbstractNode &from) = 0;
  virtual void sendEncrypted(uint8_t message[MAX_MESSAGE_LEN + 2], size_t size, const std::string &receiverId,
                             uint8_t committeeId) = 0;
  virtual bool decryptCipher(const fetch::consensus::pb::Direct_NoiseMessage &encrypted, const std::string &senderId,
                             uint8_t decrypted[MAX_MESSAGE_LEN + 2], size_t &size) = 0;

};

class AbstractDkgNode : public AbstractNode {
protected:
  AbstractDkgNode(std::string id, EventObserver &eventObserver) : AbstractNode{id, eventObserver} {}

public:
  virtual ~AbstractDkgNode() = default;
  virtual void disconnect() = 0;
  virtual void sendSignatureShare() = 0;
  virtual void enableThresholdSigning(uint32_t t) = 0;
  virtual void beginDKG() = 0;
  virtual void setSignMessages(bool sign) = 0;
};

/**
 * Node class manages connections between nodes and transport of messages irrespective of how the nodes are connected
 *
 * @tparam CryptoProtocol Crypto protocol choice
 * @tparam Derived Node type which specifies connection between nodes (either network or local)
 */
template<class CryptoProtocol, class Derived>
class Node : public AbstractDkgNode {
  using CommitteeManagerCrypto = CommitteeManager<CryptoProtocol>;

  template<typename T>
  class Neighbourhood {
    std::unordered_map<std::string, std::reference_wrapper<T>> neighbours_;
    std::set<std::string> networkMembers_;
    mutable std::mutex mutex_;

    std::vector<std::reference_wrapper<T>> neighbours() const {
      std::vector<std::reference_wrapper<T>> res;
      for (const auto &neighbour : neighbours_) {
        res.push_back(neighbour.second);
      }
      return res;
    }

    std::vector<std::reference_wrapper<T>> neighbours(const T &from) const {
      std::vector<std::reference_wrapper<T>> res;
      for (const auto &neighbour : neighbours_) {
        if (neighbour.second.get() != from) {
          res.push_back(neighbour.second);
        }
      }
      return res;
    }

  public:
    Neighbourhood(const std::string &nodeId) : networkMembers_{nodeId} {
      assert(nodeId.size() > 0);
    }

    uint32_t networkIndex(const std::string &peerId) const {
      std::lock_guard<std::mutex> lock{mutex_};
      auto iter{networkMembers_.find(peerId)};
      assert(iter != networkMembers_.end());
      return static_cast<uint32_t>(std::distance(networkMembers_.begin(), iter));
    }

    const std::set<std::string> networkMembers() const {
      std::lock_guard<std::mutex> lock{mutex_};
      return networkMembers_;
    }

    std::set<std::string> networkDiff(const std::set<std::string> &nodes) const {
      std::lock_guard<std::mutex> lock{mutex_};
      std::set<std::string> diff;
      for (const auto &n : networkMembers_) {
        if (nodes.find(n) == nodes.end()) {
          diff.insert(n);
        }
      }
      return diff;
    }

    std::size_t networkSize() const {
      std::lock_guard<std::mutex> lock{mutex_};
      return networkMembers_.size();
    }

    size_t neighboursSize() const {
      std::lock_guard<std::mutex> lock{mutex_};
      return neighbours_.size();
    }

    bool check(const std::string &node) const {
      std::lock_guard<std::mutex> lock{mutex_};
      return (neighbours_.find(node) != neighbours_.end());
    }

    void join(T &node) const {
      node.join(networkMembers_, neighbours());
    }

    void join(const std::set<std::string> &nodes, T &node, const T &from) const {
      std::lock_guard<std::mutex> lock{mutex_};
      node.join(nodes, neighbours(from));
    }

    void gossip(GossipKey gossipKey, bool gossip, const std::string &msg, const ECDSASignature &signature,
                const std::string &emitter, T &node) const {
      std::lock_guard<std::mutex> lock{mutex_};
      for (const auto &neighbour: neighbours_) {
        node.gossip(gossipKey, gossip, msg, signature, emitter, neighbour.second);
      }
    }

    void gossip(GossipKey gossipKey, bool gossip, const std::string &msg, const ECDSASignature &signature,
                const std::string &emitter, const T &from,
                T &node) const {
      std::lock_guard<std::mutex> lock{mutex_};
      for (const auto &neighbour: neighbours_) {
        if (neighbour.second.get() != from)
          node.gossip(gossipKey, gossip, msg, signature, emitter, neighbour.second);
      }
    }

    void
    broadcast(GossipKey gossipKey, bool gossip, const std::string &msg, const ECDSASignature &signature,
              const std::string &emitter, T &node) const {
      std::lock_guard<std::mutex> lock{mutex_};
      for (const auto &member : networkMembers_) {
        if (member != emitter) {
          auto iter = neighbours_.find(member);
          assert(iter != neighbours_.end());
          node.gossip(gossipKey, gossip, msg, signature, emitter, iter->second);
        }
      }
    }

    void unicast(GossipKey gossipKey, bool gossip, const std::string &msg, const ECDSASignature &signature,
                 const std::string &emitter,
                 const std::string &destination, T &node) const {
      std::lock_guard<std::mutex> lock{mutex_};
      auto iter = neighbours_.find(destination);
      assert(iter != neighbours_.end());
      node.gossip(gossipKey, gossip, msg, signature, emitter, iter->second);
    }

    bool updateNeighbour(T &neighbour) {
      std::lock_guard<std::mutex> lock{mutex_};
      if (neighbours_.find(neighbour.id()) == neighbours_.end()) {
        neighbours_.insert({neighbour.id(), neighbour});
        networkMembers_.insert(neighbour.id()); // it is a known node now.
        return true;
      }
      return false;
    }

    bool updateNetwork(const std::string &node) {
      std::lock_guard<std::mutex> lock{mutex_};
      if (networkMembers_.find(node) == networkMembers_.end()) {
        networkMembers_.insert(node);
        return true;
      }
      return false;
    }

    T *getNeighbour(const std::string &name) const {
      std::lock_guard<std::mutex> lock{mutex_};
      auto iter = neighbours_.find(name);
      if (iter == neighbours_.end())
        return nullptr;
      return &(iter->second.get());
    }
  };

  bool updateGossip(GossipKey gossipKey);

protected:
  std::atomic<uint32_t> gossipCounter_{1};
  mutable std::mutex mutex_;

  Neighbourhood<Derived> neighbourhood_;
  std::unordered_set<GossipKey> gossips_;

  // ECDSA and Diffie Hellman keys
  ECDSAKey ecdsaKey_;
  NoiseDHState *dhKeys_;
  std::unordered_map<std::string, NoiseHandshakeState *> ongoingHandshakes_;
  std::unordered_map<std::string, std::pair<NoiseCipherState *, NoiseCipherState *>> privateChannelCiphers_;
  std::pair<std::vector<uint8_t>, ECDSASignature> signedDHKey_{};
  std::mutex handshakeMutex_;
  bool signAllMessages_{true};

  bool sendNextHandshakeMessage(const std::string &nodeId);
  void onHandshake(const fetch::consensus::pb::Direct_NoiseMessage &handshakeMsg, const std::string &nodeId);
  void onCompleteHandshake(const std::string &nodeId);
  void receivedHandshake();

  std::unique_ptr<CommitteeManagerCrypto> committeeManager_;
  fetch::consensus::Logger logger = fetch::consensus::Logger("node");

  /// Network management
  /// @{
  void addNewNeighbour(const std::set<std::string> &newNodes, Derived &neighbour);
  void onNewNeighbour();
  /// @}

  /// Helper functions
  /// @{
  Derived &derived();
  GossipKey gossipId();
  std::size_t networkSize() const override;
  /// @}

public:
  explicit Node(std::string id, EventObserver &eventObserver);

  virtual ~Node() {
    noise_dhstate_free(dhKeys_);
    ongoingHandshakes_.clear();
    privateChannelCiphers_.clear();
    logger.trace("~Node {}", id_);
  }

  bool startHandShake(std::string nodeId);
  void sendEncrypted(uint8_t message[MAX_MESSAGE_LEN + 2], size_t size, const std::string &receiverId,
                     uint8_t committeeId) override;
  bool decryptCipher(const fetch::consensus::pb::Direct_NoiseMessage &encrypted, const std::string &senderId,
                     uint8_t decrypted[MAX_MESSAGE_LEN + 2], size_t &size) override;

  /// Network management
  /// @{
  void disconnect() override;
  void addNeighbour(Derived &node);
  /// @}

  /// Message handlers
  /// @{
  void onJoin(const std::set<std::string> &newNodes, AbstractNode &from) override;
  void onGossip(GossipKey gossipKey, bool gossip, const std::string &message, const ECDSASignature &signature,
                const std::string &emitter,
                AbstractNode &from) override;
  void onBroadcast(const std::string &message, std::string from) override;
  /// @}

  /// Message sending
  /// @{
  void sendGossip(const Gossip &message, GossipKey gossipKey = 0) override;
  void sendDirect(const fetch::consensus::pb::Direct &msg, const std::string &peerId) override;
  void sendSignatureShare() override;
  /// @}

  uint32_t networkIndex() const override;
  void beginDKG() override;
  void enableThresholdSigning(uint32_t t) override;
  void setDkgOutput(const std::set<std::string> &committee, const typename CryptoProtocol::DkgOutput &);
  std::string ECDSAPublicKey() const;
  std::pair<std::vector<uint8_t>, ECDSASignature> signedDHPublicKey() const;
  void setSignMessages(bool sign) override;
};
}
}
