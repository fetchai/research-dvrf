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
 * Local connection node which allows a latency to be set for each node to delay delivery of messages
 *
 * @tparam CryptoType Crypto type in DKG
 */
template<class CryptoType>
class LocalNode : public Node<CryptoType, LocalNode<CryptoType>> {
  using ECDSASignature = ECDSAKey::ECDSASignature;

  struct GossipParams {
    uint64_t step;
    bool broadcast;
    std::string msg;
    ECDSASignature signature;
    std::string emitter;
    std::string destination;
  };
  using time_point = asio::chrono::time_point<asio::chrono::steady_clock>;

  struct comparePairs {
    bool operator()(const std::pair<time_point, GossipParams> &lhs, const std::pair<time_point, GossipParams> &rhs) {
      return lhs.first < rhs.first;
    }
  };

  Scheduler &scheduler_;
  double latency_ms_;
  asio::io_context &io_context_;
  std::mutex mutex_;
  std::priority_queue<std::pair<time_point, GossipParams>, std::vector<std::pair<time_point, GossipParams>>, comparePairs> priorityQueue_;
  asio::steady_timer timer_;
  std::unordered_map<std::string, uint32_t> wait_ms_;
  std::atomic<bool> timer_set_{false};

  static fetch::consensus::Logger logger;

  void processPriorityQueue() {
    logger.trace("Node {} process queue", this->id_);
    assert(!priorityQueue_.empty());
    do {
      auto g = priorityQueue_.top().second;
      priorityQueue_.pop();
      scheduler_.gossip(g.step, g.broadcast, g.msg, g.signature, g.emitter, g.destination, *this);
    } while (!priorityQueue_.empty() and
             (asio::chrono::duration_cast<asio::chrono::microseconds>(
                     priorityQueue_.top().first - asio::chrono::steady_clock::now()).count() <= 1000)); // 1ms
  }

  bool checkTimer(const asio::chrono::time_point<asio::chrono::steady_clock> &expiry_time) {
    if (timer_set_.load()) {
      if (timer_.expiry() <= expiry_time)
        return false;
      return timer_.expires_at(expiry_time) > 0;
    }
    timer_set_.store(true);
    timer_.expires_at(expiry_time);
    return true;
  }

  void setTimer(const asio::chrono::time_point<asio::chrono::steady_clock> &expiry_time) {
    logger.trace("setTimer {} set {}", this->id_, timer_set_);
    if (!checkTimer(expiry_time))
      return;
    timer_.async_wait([this](const asio::error_code &ec) {
      if (ec != asio::error::make_error_code(asio::error::operation_aborted)) {
        std::lock_guard<std::mutex> lock{mutex_};
        processPriorityQueue();
        timer_set_.store(false);
        if (!priorityQueue_.empty()) {
          setTimer(priorityQueue_.top().first);
        }
      }
    });
  }

  void setMatchingLatency(const std::pair<std::string, uint32_t> &neighbourLatency) {
    logger.trace("set latency {} to neighbour {} of {}", this->id_, neighbourLatency.first, neighbourLatency.second);
    wait_ms_.insert(neighbourLatency);
  }

  void addNeighbourLatency(const std::string &neighbourId) {
    std::gamma_distribution<double> latency{2.0, 2.0};
    static std::minstd_rand gen{std::random_device{}()};
    auto wait{static_cast<uint32_t>(std::round(latency(gen) * latency_ms_ / 4.0))};
    logger.trace("set latency {} to neighbour {} of {}", this->id_, neighbourId, wait);
    wait_ms_.insert({neighbourId, wait});
    auto *neighbour = this->neighbourhood_.getNeighbour(neighbourId);
    assert(neighbour);
    neighbour->setMatchingLatency({this->id_, wait});
  }

public:
  explicit LocalNode(std::string name, EventObserver &eventObserver,
                     Scheduler &scheduler, double latency_ms = 120.0)  //Based on Ethereum network
          : Node<CryptoType, LocalNode>{std::move(name), eventObserver}, scheduler_{scheduler}, latency_ms_{latency_ms},
            io_context_{scheduler_.getIoContext()}, timer_{io_context_} {
    scheduler_.connect(*this);
  }

  virtual ~LocalNode() {
    disconnect();
  }

  void disconnect() {
    std::lock_guard<std::mutex> lock{mutex_};
    scheduler_.disconnect(*this);
    timer_.cancel();
  }

  void join(const std::set<std::string> &newNodes, const LocalNode &destination) {
    logger.trace("join {} to {}", this->id_, destination.id());
    if (wait_ms_.find(destination.id()) == wait_ms_.end()) {
      addNeighbourLatency(destination.id());
    }
    scheduler_.join(newNodes, {destination.id()}, *this);
  }

  void join(const std::set<std::string> &newNodes, const std::vector<std::reference_wrapper<LocalNode>> &destinations) {
    logger.trace("join {} to all", this->id_);
    std::vector<std::string> p;
    for (auto &destination : destinations) {
      if (wait_ms_.find(destination.get().id()) == wait_ms_.end()) {
        addNeighbourLatency(destination.get().id());
      }
      p.push_back(destination.get().id());
    }
    scheduler_.join(newNodes, p, *this);
  }

  void gossip(uint64_t step, bool broadcast, const std::string &msg, const ECDSASignature &signature,
              const std::string &emitter,
              const Node<CryptoType, LocalNode> &destination) {
    std::lock_guard<std::mutex> lock{mutex_};
    logger.trace("gossip {} to {}", this->id_, destination.id());
    assert(wait_ms_.find(destination.id()) != wait_ms_.end());
    asio::chrono::time_point<asio::chrono::steady_clock> expiry_time{
            asio::chrono::steady_clock::now() + asio::chrono::milliseconds{wait_ms_.at(destination.id())}};
    priorityQueue_.push({expiry_time, GossipParams{step, broadcast, msg, signature, emitter, destination.id()}});
    setTimer(expiry_time);
  }

  void addAllNeighbours(const std::vector<std::unique_ptr<LocalNode>> &all_nodes, uint32_t threshold) {
    std::set<std::string> committee;
    for (const auto &node : all_nodes) {
      if (node->id() != this->id_ and this->neighbourhood_.updateNeighbour(*node)) {
        if (wait_ms_.find(node->id()) == wait_ms_.end()) {
          addNeighbourLatency(node->id());
        }
      }
      committee.insert(node->id());
    }
    this->committeeManager_ = std::unique_ptr<CommitteeManager<CryptoType>>(
            new CommitteeManager<CryptoType>{committee, *this, threshold});
  }
};

template<class CryptoType>
fetch::consensus::Logger LocalNode<CryptoType>::logger = fetch::consensus::Logger("localnode");
}
};
