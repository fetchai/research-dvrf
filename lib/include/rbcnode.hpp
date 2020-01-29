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
#include "rbc.hpp"
#include "scheduler.hpp"
#include <atomic>
#include <bitset>
#include <algorithm>
#include <google/protobuf/text_format.h>

namespace fetch {
namespace consensus {

/**
 * Node specifically for testing the RBC, which operates as a simple node
 */
class RBCNode : public AbstractNode {
public:
  enum class Failures : uint8_t {
    BAD_MESSAGE, BAD_HASH, NO_ECHO, NO_READY, NO_ANSWER, BAD_ANSWER, DOUBLE_SEND, WRONG_RANK
  };
private:
  using ECDSASignature = ECDSAKey::ECDSASignature;

  std::unordered_map<std::string, std::reference_wrapper<RBCNode>> neighbours_;
  Scheduler &scheduler_;
  std::set<std::string> miners_;
  RBC rbc_;
  std::atomic<uint32_t> gossip_counter_{1};
  std::mutex mutex_;

  static fetch::consensus::Logger logger;

  std::bitset<static_cast<int>(Failures::WRONG_RANK) + 1> failures_flags_;

  std::string to_string(const google::protobuf::Message &msg) const {
    std::string output;
    google::protobuf::TextFormat::PrintToString(msg, &output);
    return output;
  }

  bool failure(Failures f) const {
    return failures_flags_[static_cast<int>(f)];
  }

  GossipKey gossip_id() {
    GossipKey gossip_id = ((networkIndex() << 16) + gossip_counter_.load());
    ++gossip_counter_;
    return gossip_id;
  }

  void addNewNeighbour(const std::set<std::string> &newNodes, RBCNode &neighbour) {
    logger.trace("addNewNeighbour {} nodes {} from {}", id_, t_to_string(newNodes),
                 neighbour.id());
    neighbours_.insert({neighbour.id(), neighbour});
    std::set<std::string> diff;
    for (const auto &n : miners_) {
      if (newNodes.find(n) == newNodes.end()) {
        diff.insert(n);
      }
    }
    if (!diff.empty()) {
      scheduler_.join(diff, {neighbour.id()}, *this);
    }
    miners_.insert(neighbour.id()); // it is a known node now.
  }

public:
  RBCNode(std::string name, EventObserver &eventObserver, std::set<std::string> committee, uint32_t threshold,
          Scheduler &scheduler,
          const std::vector<Failures> &failures = {}) :
          AbstractNode{std::move(name), eventObserver}, scheduler_{scheduler}, rbc_{std::move(committee), *this, threshold} {
    miners_.insert(id_);
    scheduler_.connect(*this);
    for (auto f : failures) {
      failures_flags_.set(static_cast<int>(f));
    }
  }

  virtual ~RBCNode() {
    scheduler_.disconnect(*this);
  }

  std::vector<std::string> neighbours() const {
    std::vector<std::string> res;
    for (auto &n : neighbours_) {
      res.push_back(n.second.get().id());
    }
    return res;
  }

  uint32_t networkIndex() const override {
    auto from_iter{miners_.find(id_)};
    assert(from_iter != miners_.end());
    return static_cast<uint32_t>(std::distance(miners_.begin(), from_iter));
  }

  std::size_t networkSize() const override {
    return miners_.size();
  }

  void addAllNeighbours(std::vector<std::unique_ptr<RBCNode>> &nodes) {
    std::lock_guard<std::mutex> lock(mutex_);
    assert(neighbours_.size() == 0);
    for (auto &n : nodes) {
      if (n->id() != id_)
        neighbours_.insert({n->id(), *n});
      miners_.insert(n->id());
    }
  }

  void addNeighbour(RBCNode &node) {
    logger.trace("addNeighbour {} node {} new {}", id_, node.id(), (neighbours_.find(node.id()) == neighbours_.end()));
    std::lock_guard<std::mutex> lock(mutex_);
    if (neighbours_.find(node.id()) == neighbours_.end()) {
      neighbours_.insert({node.id(), node});
      miners_.insert(node.id()); // it is a known node now.
      std::vector<std::string> param;
      for (const auto &neighbour : neighbours_) {
        param.push_back(neighbour.second.get().id());
      }
      scheduler_.join(miners_, param, *this);
    }
  }

  void onJoin(const std::set<std::string> &newNodes, AbstractNode &from) override {
    logger.trace("onJoin {} nodes {} from {}", id_, t_to_string(newNodes), from.id());
    std::lock_guard<std::mutex> lock(mutex_);

    std::set<std::string> reallyNewNodes;

    // first, if it is a new neighbour, let's send the known nodes minus the new nodes
    if (neighbours_.find(from.id()) == neighbours_.end()) {
      reallyNewNodes.insert(from.id()); // the new neighbour need to be propagated too.
      addNewNeighbour(newNodes, dynamic_cast<RBCNode &>(from));
      logger.trace("addNewNeighbour after {} nodes {} currentNodes {} from {}", id_, t_to_string(newNodes),
                   t_to_string(miners_), from.id());
    }

    // second, let's send the new nodes to the known neighbours (minus the origin of the update)
    for (const auto &newNode : newNodes) {
      if (newNode != id_ && miners_.find(newNode) == miners_.end()) {
        miners_.insert(newNode);
        reallyNewNodes.insert(newNode);
      }
    }

    if (!reallyNewNodes.empty()) {
      std::vector<std::string> param;
      for (const auto &neighbour: neighbours_) {
        if (neighbour.second.get() != dynamic_cast<RBCNode &>(from)) {
          param.push_back(neighbour.second.get().id());
        }
      }
      scheduler_.join(reallyNewNodes, param, *this);
    }
  }

  void onGossip(GossipKey, bool, const std::string &message, const ECDSASignature &, const std::string&, AbstractNode &from) override {
    fetch::consensus::pb::Direct msg;
    msg.ParseFromString(message);
    rbc_.onRBC(msg.rbc_msg(), from.networkIndex());
  }

  void sendBroadcast(const std::string &debugString) {
    fetch::consensus::pb::Broadcast broadcast_msg;
    auto *complaints_msg = broadcast_msg.mutable_complaints();
    complaints_msg->add_nodes(debugString);
    rbc_.broadcast(broadcast_msg);
  }

  void changeRank(fetch::consensus::pb::Direct_RBC_Tag &tag) const {
    tag.set_rank((tag.rank() + 1) % rbc_.size());
  }

  void changeMessage(fetch::consensus::pb::Direct_RBC_Tag &tag, fetch::consensus::pb::Direct_RBC_Message &msg) const {
    if (failure(Failures::WRONG_RANK)) {
      changeRank(tag);
    }
    if (failure(Failures::BAD_MESSAGE)) {
      auto s = msg.message();
      std::reverse(s.begin(), s.end());
      msg.set_message(s);
    }
  }

  void changeHash(fetch::consensus::pb::Direct_RBC_Tag &tag, fetch::consensus::pb::Direct_RBC_Hash &msg) const {
    if (failure(Failures::WRONG_RANK)) {
      changeRank(tag);
    }
    if (failure(Failures::BAD_HASH)) {
      auto hash = msg.msg_hash() + "1";
      logger.info("changeHash from {} to {} old {} new {}", id(), tag.rank(), msg.msg_hash(), hash);
      msg.set_msg_hash(hash);
    }
  }

  void changeMsg(fetch::consensus::pb::Direct_RBC &msg) const {
    switch (msg.payload_case()) {
      case fetch::consensus::pb::Direct_RBC::kBroadcast:
        changeMessage(*(msg.mutable_tag()), *(msg.mutable_broadcast()));
        break;
      case fetch::consensus::pb::Direct_RBC::kEcho:
        changeHash(*(msg.mutable_tag()), *(msg.mutable_echo()));
        break;
      case fetch::consensus::pb::Direct_RBC::kReady:
        changeHash(*(msg.mutable_tag()), *(msg.mutable_ready()));
        break;
      case fetch::consensus::pb::Direct_RBC::kRequest:
        changeRank(*(msg.mutable_tag()));
        break;
      case fetch::consensus::pb::Direct_RBC::kAnswer:
        changeMessage(*(msg.mutable_tag()), *(msg.mutable_answer()));
        break;
      case fetch::consensus::pb::Direct_RBC::PAYLOAD_NOT_SET:
      default:
        assert(false);
    }
  }

  void sendDirect(const fetch::consensus::pb::Direct &msg, const std::string &miner_id) override {
    fetch::consensus::pb::Direct_RBC real_msg(msg.rbc_msg());
    if (failures_flags_.any()) {
      if (failure(Failures::NO_ECHO) && msg.rbc_msg().has_echo()) {
        logger.info("Skipping echo");
        return;
      }
      if (failure(Failures::NO_READY) && msg.rbc_msg().has_ready()) {
        logger.info("Skipping ready");
        return;
      }
      changeMsg(real_msg);
    }

    assert(msg.has_committee_id());
    std::string serialized_msg;
    bool ok = msg.SerializeToString(&serialized_msg);
    assert(ok);
    (void) ok;
    // Do not compute and verify signatures here
    ECDSASignature signature;
    if (miner_id.empty()) {
      for (const auto &miner : miners_) {
        if (miner != id_) {
          auto iter = neighbours_.find(miner);
          assert(iter != neighbours_.end());
          scheduler_.gossip(gossip_id(), false, serialized_msg, signature, id_, iter->second.get().id(), *this);
          if (failure(Failures::DOUBLE_SEND)) {
            scheduler_.gossip(gossip_id(), false, serialized_msg, signature, id_, iter->second.get().id(), *this);
          }
        }
      }
    } else {
      assert(false);
    }
  }

  void sendGossip(const Gossip &, GossipKey) override {
    assert(false);
  }

  void onBroadcast(const std::string &message, std::string from_id) override {
    logger.trace("onBroadcast {} received from {} message {}", id_, from_id, message);
  }

  void sendEncrypted(uint8_t [MAX_MESSAGE_LEN + 2], size_t, const std::string &, uint8_t) override {
    assert(false);
  }

  bool
  decryptCipher(const fetch::consensus::pb::Direct_NoiseMessage &, const std::string &, uint8_t [MAX_MESSAGE_LEN + 2],
                size_t &) override {
    assert(false);
    return false;
  }
};
}
}
