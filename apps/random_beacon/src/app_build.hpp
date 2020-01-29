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

#include "localnode.hpp"
#include "simplenode.hpp"
#include "networknode.hpp"

using namespace fetch::consensus;

class DKGEventObserver : public EventObserver {
  std::mutex m_group_sig_;
  std::mutex m_sign_;
  std::condition_variable cv_sign_;
  uint32_t committee_size_;
  std::set<std::string> beacon_completed_;
  std::unordered_set<std::string> signatures_computed_;
  uint32_t counter{1};
public:
  explicit DKGEventObserver(uint32_t committee_size) : committee_size_{committee_size} {}

  void notifyNewConnection(const std::string &, const std::string &) override {}

  void notifyCommitteeSync(const std::string &) override {}

  void notifyRBCDeliver(const tag_type &, uint32_t, uint32_t) override {}

  void notifyDKGCompleted(const std::string &, const Duration &, const std::string &) override {}

  void notifyBroadcastSignature(const std::string &,
                                std::chrono::time_point<std::chrono::high_resolution_clock>) override {}

  void notifyGroupSignature(const std::string &, const std::string &signature) override {
    std::unique_lock<std::mutex> mlock(m_group_sig_);
    if (signatures_computed_.find(signature) == signatures_computed_.end()) {
      fetch::consensus::SHA3_512 sigHash{signature};
      std::cout << "Round: " << counter << ", Random Value: " << sigHash.toString() << std::endl;
      std::cout << std::endl;
      signatures_computed_.insert(signature);
      ++counter;
    }
  }

  void notifySignedMessage(const std::string &id,
                           std::chrono::time_point<std::chrono::high_resolution_clock>) override {
    std::unique_lock<std::mutex> mlock(m_sign_);
    beacon_completed_.insert(id);
    mlock.unlock();
    cv_sign_.notify_one();
  }

  void waitForSignedMessage() {
    std::unique_lock<std::mutex> mlock(m_sign_);
    while (beacon_completed_.size() < committee_size_) {
      cv_sign_.wait(mlock);
    }
  }
};

template<class Drb>
std::vector<std::unique_ptr<fetch::consensus::AbstractDkgNode>>
build(bool networked, double latency, EventObserver &obs, uint32_t committee_size, uint32_t threshold,
      Scheduler &scheduler, bool signMessages) {
  using LocalNodeCrypto = LocalNode<Drb>;
  using SimpleNodeCrypto = SimpleNode<Drb>;
  using NetworkNodeCrypto = NetworkNode<Drb>;

  Drb::initCrypto();
  auto outputs = Drb::trustedDealer(committee_size, threshold);
  assert(outputs.size() == committee_size);

  if (networked) {
    std::vector<std::unique_ptr<NetworkNodeCrypto>> all_nodes;
    std::set<std::string> committee;
    for (uint16_t iv = 0; iv < committee_size; ++iv) {
      all_nodes.emplace_back(
              new NetworkNodeCrypto("Node" + std::to_string(iv), obs,
                                    scheduler.getIoContext(), 1024 + iv));
      committee.insert("Node" + std::to_string(iv));
    }
    for (auto &node : all_nodes) {
      node->setSignMessages(signMessages);
    }
    for (auto &node : all_nodes) {
      node->addAllNeighbours(all_nodes, threshold);
      node->setDkgOutput(committee, outputs[node->networkIndex()]);
    }
    std::vector<std::unique_ptr<fetch::consensus::AbstractDkgNode>> ret;
    for (auto &node : all_nodes) {
      ret.emplace_back(std::move(node));
    }
    return ret;
  }
  if (latency > 0) {
    std::vector<std::unique_ptr<LocalNodeCrypto>> all_nodes;
    std::set<std::string> committee;
    for (uint32_t iv = 0; iv < committee_size; ++iv) {
      all_nodes.emplace_back(
              new LocalNodeCrypto("Node" + std::to_string(iv), obs, scheduler, latency));
      committee.insert("Node" + std::to_string(iv));
    }
    for (auto &node : all_nodes) {
      node->addAllNeighbours(all_nodes, threshold);
      node->setDkgOutput(committee, outputs[node->networkIndex()]);
    }
    std::vector<std::unique_ptr<fetch::consensus::AbstractDkgNode>> ret;
    for (auto &node : all_nodes) {
      ret.emplace_back(std::move(node));
    }
    return ret;
  }
  std::vector<std::unique_ptr<SimpleNodeCrypto>> all_nodes;
  std::set<std::string> committee;
  for (uint32_t iv = 0; iv < committee_size; ++iv) {
    all_nodes.emplace_back(
            new SimpleNodeCrypto("Node" + std::to_string(iv), obs, scheduler));
    committee.insert("Node" + std::to_string(iv));
  }
  for (auto &node : all_nodes) {
    node->addAllNeighbours(all_nodes, threshold);
    node->setDkgOutput(committee, outputs[node->networkIndex()]);
  }

  std::vector<std::unique_ptr<fetch::consensus::AbstractDkgNode>> ret;
  for (auto &node : all_nodes) {
    ret.emplace_back(std::move(node));
  }
  return ret;
}
