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

#define CATCH_CONFIG_ENABLE_BENCHMARKING

#include "catch.hpp"
#include "node_impl.hpp"
#include "rbcnode.hpp"
#include <iostream>
#include <chrono>
#include "threadpool.hpp"
#include <condition_variable>

using namespace fetch::consensus;

class RBCEventObserver : public EventObserver {
  std::mutex m_;
  std::condition_variable conditionVariable_;
  uint32_t committee_size_;
  std::unordered_map<tag_type, std::unordered_set<uint32_t>> rbc_stats_;
  std::unordered_set<tag_type> fully_delivered_;
public:
  explicit RBCEventObserver(uint32_t committee_size) : committee_size_{committee_size} {}

  void notifyNewConnection(const std::string &, const std::string &) override {}

  void notifyCommitteeSync(const std::string &) override {}

  void notifyDKGCompleted(const std::string &, const Duration &, const std::string &) override {}

  void notifyBroadcastSignature(const std::string &,
                                std::chrono::time_point<std::chrono::high_resolution_clock>) override {};

  void notifySignedMessage(const std::string &, std::chrono::time_point<std::chrono::high_resolution_clock>) override {}

  void notifyGroupSignature(const std::string &, const std::string &) override {};

  void waitForRBCDeliver(size_t nbMsgs, uint32_t t) {
    size_t deliveries = nbMsgs * (committee_size_ - t);
    std::unique_lock<std::mutex> mlock(m_);
    while (fully_delivered_.size() < deliveries)
      conditionVariable_.wait(mlock);
    std::cerr << "All delivered.\n";
  }

  void notifyRBCDeliver(const tag_type &tag, uint32_t from_rank, uint32_t to_rank) override {
    std::unique_lock<std::mutex> mlock(m_);
    rbc_stats_[tag].insert(to_rank);
    if (rbc_stats_[tag].size() == committee_size_ - 1) {
      std::cerr << "tag " << tag << " from " << from_rank << " fully delivered\n";
      fully_delivered_.insert(tag);
    }
    mlock.unlock();
    conditionVariable_.notify_one();
    //std::cerr << "deliver tag " << tag << " from " << from_rank << " to " << to_rank << std::endl;
  };
};

TEST_CASE("rbc", "[rbc]") {
  Scheduler scheduler{4};
  {
    uint32_t committee_size{20};
    uint32_t threshold{6};

    std::set<std::string> committee;
    for (uint32_t i = 1; i <= committee_size; ++i) {
      committee.insert("Node" + std::to_string(i));
    }
    RBCEventObserver obs{committee_size};

    std::vector<std::unique_ptr<RBCNode>> nodes;
    for (const auto &member : committee) {
      nodes.emplace_back(new RBCNode{member, obs, committee, threshold, scheduler});
    }
    for (auto &n : nodes) {
      n->addAllNeighbours(nodes);
    }

    for (auto &n : nodes) {
      n->sendBroadcast("DebugMessage");
      n->sendBroadcast("DebugMessage2");
    }
    obs.waitForRBCDeliver(2, 0);
    std::this_thread::sleep_for(std::chrono::seconds{1});
    scheduler.stop();
  }
}

TEST_CASE("rbc double send", "[rbc]") {
  Scheduler scheduler{4};
  {
    uint32_t committee_size{20};
    uint32_t threshold{6};

    std::set<std::string> committee;
    for (uint32_t i = 1; i <= committee_size; ++i) {
      committee.insert("Node" + std::to_string(i));
    }
    RBCEventObserver obs{committee_size};

    std::vector<std::unique_ptr<RBCNode>> nodes;
    for (const auto &member : committee) {
      nodes.emplace_back(new RBCNode{member, obs, committee, threshold, scheduler,
                                     {RBCNode::Failures::DOUBLE_SEND}});
    }
    for (auto &n : nodes) {
      n->addAllNeighbours(nodes);
    }

    for (auto &n : nodes) {
      n->sendBroadcast("DebugMessage");
      n->sendBroadcast("DebugMessage2");
    }
    obs.waitForRBCDeliver(2, 0);
    std::this_thread::sleep_for(std::chrono::seconds{1});
    scheduler.stop();
  }
}

TEST_CASE("rbc wrong rank", "[rbc]") {
  Scheduler scheduler{4};
  {
    uint32_t committee_size{20};
    uint32_t threshold{6};

    std::set<std::string> committee;
    for (uint32_t i = 1; i <= committee_size; ++i) {
      committee.insert("Node" + std::to_string(i));
    }
    RBCEventObserver obs{committee_size};

    std::vector<std::unique_ptr<RBCNode>> nodes;
    uint32_t i = 0;
    for (const auto &member : committee) {
      if (i <= threshold) {
        nodes.emplace_back(new RBCNode{member, obs, committee, threshold, scheduler,
                                       {RBCNode::Failures::WRONG_RANK}});
      } else {
        nodes.emplace_back(new RBCNode{member, obs, committee, threshold, scheduler, {}});
      }
      ++i;
    }
    for (auto &n : nodes) {
      n->addAllNeighbours(nodes);
    }

    for (auto &n : nodes) {
      n->sendBroadcast("DebugMessage");
      n->sendBroadcast("DebugMessage2");
    }
    obs.waitForRBCDeliver(2, threshold);
    std::this_thread::sleep_for(std::chrono::seconds{1});
    scheduler.stop();
  }
}

TEST_CASE("rbc no echo", "[rbc]") {
  Scheduler scheduler{4};
  {
    uint32_t committee_size{20};
    uint32_t threshold{6};

    std::set<std::string> committee;
    for (uint32_t i = 1; i <= committee_size; ++i) {
      committee.insert("Node" + std::to_string(i));
    }
    RBCEventObserver obs{committee_size};

    std::vector<std::unique_ptr<RBCNode>> nodes;
    uint32_t i = 0;
    for (const auto &member : committee) {
      if (i <= threshold) {
        nodes.emplace_back(new RBCNode{member, obs, committee, threshold, scheduler,
                                       {RBCNode::Failures::NO_ECHO}});
      } else {
        nodes.emplace_back(new RBCNode{member, obs, committee, threshold, scheduler, {}});
      }
      ++i;
    }
    for (auto &n : nodes) {
      n->addAllNeighbours(nodes);
    }

    for (auto &n : nodes) {
      n->sendBroadcast("DebugMessage");
      n->sendBroadcast("DebugMessage2");
    }
    obs.waitForRBCDeliver(2, threshold);
    std::this_thread::sleep_for(std::chrono::seconds{1});
    scheduler.stop();
  }
}

TEST_CASE("rbc no ready", "[rbc]") {
  Scheduler scheduler{4};
  {
    uint32_t committee_size{20};
    uint32_t threshold{6};

    std::set<std::string> committee;
    for (uint32_t i = 1; i <= committee_size; ++i) {
      committee.insert("Node" + std::to_string(i));
    }
    RBCEventObserver obs{committee_size};

    std::vector<std::unique_ptr<RBCNode>> nodes;
    uint32_t i = 0;
    for (const auto &member : committee) {
      if (i <= threshold) {
        nodes.emplace_back(new RBCNode{member, obs, committee, threshold, scheduler,
                                       {RBCNode::Failures::NO_READY}});
      } else {
        nodes.emplace_back(new RBCNode{member, obs, committee, threshold, scheduler, {}});
      }
      ++i;
    }
    for (auto &n : nodes) {
      n->addAllNeighbours(nodes);
    }

    for (auto &n : nodes) {
      n->sendBroadcast("DebugMessage");
      n->sendBroadcast("DebugMessage2");
    }
    obs.waitForRBCDeliver(2, threshold);
    std::this_thread::sleep_for(std::chrono::seconds{1});
    scheduler.stop();
  }
}