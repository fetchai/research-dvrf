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
#include "scheduler.hpp"
#include <chrono>

namespace fetch {
namespace consensus {

/**
 * A local node setup with scheduler for message deliver that has no latency in message delivery
 *
 * @tparam CryptoType Crypto type in DKG
 */
template<class CryptoType>
class SimpleNode : public Node<CryptoType, SimpleNode<CryptoType>> {
  using ECDSASignature = ECDSAKey::ECDSASignature;

  Scheduler &scheduler_;

  static fetch::consensus::Logger logger;

public:
  explicit SimpleNode(std::string name, EventObserver &eventObserver, Scheduler &scheduler)
          : Node<CryptoType, SimpleNode>{std::move(name), eventObserver}, scheduler_{scheduler} {
    scheduler_.connect(*this);
  }

  virtual ~SimpleNode() {
    scheduler_.disconnect(*this);
  }

  void disconnect() {
    scheduler_.disconnect(*this);
  }

  void join(const std::set<std::string> &newNodes, const SimpleNode &destination) {
    logger.trace("join {} to {}", this->id_, destination.id());
    scheduler_.join(newNodes, {destination.id()}, *this);
  }

  void
  join(const std::set<std::string> &newNodes, const std::vector<std::reference_wrapper<SimpleNode>> &destinations) {
    logger.trace("join {} to all", this->id_);
    std::vector<std::string> p;
    for (auto &destination : destinations) {
      p.push_back(destination.get().id());
    }
    scheduler_.join(newNodes, p, *this);
  }

  void gossip(uint64_t step, bool broadcast, const std::string &msg, const ECDSASignature &signature, const std::string &emitter,
              const Node <CryptoType, SimpleNode> &destination) {
    logger.trace("gossip {} to {}", this->id_, destination.id());
    scheduler_.gossip(step, broadcast, msg, signature, emitter, destination.id(), *this);
  }

  void addAllNeighbours(const std::vector<std::unique_ptr<SimpleNode>> &all_nodes, uint32_t threshold) {
    std::set<std::string> committee;
    for (const auto &node : all_nodes) {
      if (node->id() != this->id_) {
        this->neighbourhood_.updateNeighbour(*node);
      }
      committee.insert(node->id());
    }
    this->committeeManager_ = std::unique_ptr<CommitteeManager<CryptoType>>(
            new CommitteeManager<CryptoType>{committee, *this, threshold});
  }
};

template<class CryptoType>
fetch::consensus::Logger SimpleNode<CryptoType>::logger = fetch::consensus::Logger("simplenode");
}
};
