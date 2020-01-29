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

#include "scheduler.hpp"
#include "localnode.hpp"
#include "rbcnode.hpp"
#include "simplenode.hpp"

namespace fetch {
namespace consensus {

fetch::consensus::Logger Scheduler::logger = fetch::consensus::Logger("scheduler");
fetch::consensus::Logger RBCNode::logger = fetch::consensus::Logger("rbcnode");

void Scheduler::connect(AbstractNode &node) {
  std::lock_guard<std::mutex> lock(mutex_);
  logger.trace("connect {}", node.id());
  auto p = nodes_.insert({node.id(), node});
  assert(p.second);
  (void) p;
}

void Scheduler::disconnect(AbstractNode &node) {
  std::lock_guard<std::mutex> lock(mutex_);
  logger.trace("disconnect {}", node.id());
  nodes_.erase(node.id());
}

void Scheduler::join(const std::set<std::string> &newNodes, const std::vector<std::string> &destinations,
                     AbstractNode &from) {
  std::lock_guard<std::mutex> lock(mutex_);
  logger.trace("join {} to all neighbours from {}", t_to_string(newNodes), from.id());
  msg_queue_.push({destinations, JoinParams{newNodes, from}});
}

void Scheduler::gossip(uint64_t step, bool broadcast, const std::string &msg, const ECDSASignature &signature,
                       const std::string &emitter,
                       const std::string &destination, AbstractNode &from) {
  logger.trace("gossip step {} origin {} to {} from {}", step, emitter, destination, from.id());
  msg_queue_.push({{destination}, GossipParams{step, broadcast, msg, signature, emitter, from}});
}

void Scheduler::process() {
  while (!stopping_) {
    auto p = msg_queue_.pop();
    if (!stopping_) {
      p.second.match(
              [&p, this](const JoinParams &params) {
                for (auto &s : p.first) {
                  auto iter = nodes_.find(s);
                  if (iter != nodes_.end()) {
                    // distribute messages
                    iter->second.get().onJoin(params.newNodes, params.from);
                  }
                }
              },
              [&p, this](const GossipParams &params) {
                for (auto &s : p.first) {
                  auto iter = nodes_.find(s);
                  if (iter != nodes_.end()) {
                    // distribute messages
                    iter->second.get().onGossip(params.step, params.broadcast, params.msg, params.signature,
                                                params.emitter, params.from);
                  }
                }
              },
              [this](stde::nullopt_t) {
                stopping_ = true;
              });
    }
  }
}
}
}
