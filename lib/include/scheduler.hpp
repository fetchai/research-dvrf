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

#include "queue.hpp"
#include "logger.hpp"
#include "mapbox/variant.hpp"
#include "network.hpp"
#include <set>
#include <iostream>

#if __cplusplus >= 201701L
#include <optional>
namespace stde = std;
#else
#if __cplusplus >= 201402L
#include <experimental/optional>
namespace stde = std::experimental;
#else
#error "C++11 and earlier not supported"
#endif
#endif

namespace var = mapbox::util; // for the variant

namespace fetch {
namespace consensus {
class AbstractNode;

class Scheduler {
  using ECDSASignature = std::vector<uint8_t>;

  struct JoinParams {
    const std::set<std::string> newNodes;
    AbstractNode &from;
  };
  struct GossipParams {
    const uint64_t step;
    const bool broadcast;
    const std::string msg;
    const ECDSASignature signature;
    const std::string emitter;
    AbstractNode &from;
  };
  using VariantType = var::variant<JoinParams, GossipParams, stde::nullopt_t>;

  IoContextPool ioContextPool_;
  std::unordered_map<std::string, std::reference_wrapper<AbstractNode>> nodes_;
  Queue<std::pair<std::vector<std::string>, VariantType>> msg_queue_;
  std::vector<std::unique_ptr<std::thread>> threads_;
  std::atomic<bool> stopping_{false};
  std::mutex mutex_;

  static fetch::consensus::Logger logger;

  void process();

public:
  explicit Scheduler(std::size_t nb_threads = 4) : ioContextPool_{nb_threads} {
    for (size_t i = 0; i < nb_threads; ++i) {
      threads_.emplace_back(new std::thread([this]() { process(); }));
    }
    ioContextPool_.run();
  }

  ~Scheduler() {
    if (!stopping_ && threads_.size() > 0)
      for (auto &t : threads_)
        t->join();
  }

  void stop() {
    logger.trace("stop {} threads {}", stopping_, threads_.size());
    stopping_ = true;
    if (threads_.size() > 0) {
      for (size_t i = 0; i < threads_.size(); ++i)
        msg_queue_.push({{}, stde::nullopt});
      for (auto &t : threads_) {
        logger.trace("stop {} threads {} thread id {} joinable {}", stopping_, threads_.size(), t->get_id(),
                     t->joinable());
        t->join();
        logger.trace("stopped {} threads {} thread id {} joinable {}", stopping_, threads_.size(), t->get_id(),
                     t->joinable());
      }
    }
    ioContextPool_.stop();
  }

  asio::io_context &getIoContext() { return ioContextPool_.getIoContext(); }

  void connect(AbstractNode &node);
  void disconnect(AbstractNode &node);
  void join(const std::set<std::string> &newNodes, const std::vector<std::string> &destinations, AbstractNode &from);
  void gossip(uint64_t step, bool broadcast, const std::string &msg, const ECDSASignature &signature, const std::string &emitter,
              const std::string &destination,
              AbstractNode &from);
};
}
}
  
