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

#include "catch.hpp"
#include "node.hpp"
#include "networknode.hpp"
#include "scheduler.hpp"

using namespace fetch::consensus;

class DKGEventObserver : public EventObserver {
  std::mutex m_sign_;
  std::mutex m_dkg_;
  std::condition_variable cv_sign_;
  std::condition_variable cv_dkg_;
  uint32_t committee_size_;
  std::set<std::string> signatures_;
  std::set<std::string> dkg_completed_;
  std::unordered_map<std::string, std::set<std::string>> public_keys;
  std::unordered_map<std::string, std::set<std::string>> group_signatures_;
public:
  explicit DKGEventObserver(uint32_t committee_size) : committee_size_{committee_size} {}

  void notifyRBCDeliver(const tag_type &, uint32_t, uint32_t) override {};

  void notifyNewConnection(const std::string &, const std::string &) override {}

  void notifyCommitteeSync(const std::string &) override {};

  void notifyBroadcastSignature(const std::string &,
                                std::chrono::time_point<std::chrono::high_resolution_clock>) override {};

  void waitForSignedMessage() {
    std::unique_lock<std::mutex> mlock(m_sign_);
    while (signatures_.size() < committee_size_) {
      cv_sign_.wait(mlock);
    }
  }

  void
  notifySignedMessage(const std::string &id, std::chrono::time_point<std::chrono::high_resolution_clock>) override {
    std::unique_lock<std::mutex> mlock(m_sign_);
    signatures_.insert(id);
    mlock.unlock();
    cv_sign_.notify_one();
  }

  void notifyGroupSignature(const std::string &message, const std::string &group_signature) override {
    std::lock_guard<std::mutex> mlock(m_sign_);
    group_signatures_[message].insert(group_signature);
  }

  void waitForDkgCompletion() {
    std::unique_lock<std::mutex> mlock(m_dkg_);
    while (dkg_completed_.size() < committee_size_) {
      cv_dkg_.wait(mlock);
    }
  }

  void notifyDKGCompleted(const std::string &id, const Duration &, const std::string &public_key_str) override {
    std::unique_lock<std::mutex> mlock(m_dkg_);
    dkg_completed_.insert(id);
    public_keys[public_key_str].insert(id);
    mlock.unlock();
    cv_dkg_.notify_one();
  }

  bool checkPublicKeys() {
    std::unique_lock<std::mutex> mlock(m_dkg_);
    return public_keys.size() == 1;
  }

  bool checkGroupSignatures(uint32_t num_rounds) {
    std::lock_guard<std::mutex> mlock(m_sign_);
    return group_signatures_.size() == num_rounds and group_signatures_.begin()->second.size() == 1;
  }
};

template<class CryptoNode>
void build_local(uint32_t committee_size, uint32_t threshold, uint32_t num_rounds) {
  Scheduler scheduler{4};
  DKGEventObserver obs{committee_size};
  std::vector<std::unique_ptr<CryptoNode>> all_nodes;
  {
    std::unordered_set<uint32_t> unset_nodes;
    std::set<std::string> committee;
    for (uint32_t iv = 0; iv < committee_size; ++iv) {
      all_nodes.emplace_back(std::move(
              new CryptoNode("Node" + std::to_string(iv), obs, scheduler)));
      unset_nodes.insert(iv);
      committee.insert("Node" + std::to_string(iv));
    }

    for (auto &node : all_nodes) {
      node->addAllNeighbours(all_nodes, threshold);
    }

    for (auto &node : all_nodes) {
      node->beginDKG();
    }

    obs.waitForDkgCompletion();

    // Test DKG result
    REQUIRE(obs.checkPublicKeys());

    //Try some threshold signing
    if (num_rounds > 0) {
      for (uint32_t kk = 0; kk < committee_size; ++kk) {
        all_nodes[kk]->enableThresholdSigning(num_rounds);
        all_nodes[kk]->sendSignatureShare();
      }

      obs.waitForSignedMessage();

      // Test signature result
      REQUIRE(obs.checkGroupSignatures(num_rounds));
    }

    scheduler.stop();
  }
}

template<class CryptoType>
void build_network(uint32_t committee_size, uint32_t threshold, uint32_t num_rounds) {
  IoContextPool pool{8};
  pool.run();
  DKGEventObserver obs{committee_size};
  std::vector<std::unique_ptr<NetworkNode<CryptoType>>> all_nodes;

  std::unordered_set<uint32_t> unset_nodes;
  std::set<std::string> committee;
  for (uint32_t iv = 0; iv < committee_size; ++iv) {
    all_nodes.emplace_back(std::move(
            new NetworkNode<CryptoType>("Node" + std::to_string(iv), obs,
                                        pool.getIoContext(), 1024 + iv)));
    unset_nodes.insert(iv);
    committee.insert("Node" + std::to_string(iv));
  }

  for (auto &node : all_nodes) {
    node->addAllNeighbours(all_nodes, threshold);
  }
  std::this_thread::sleep_for(std::chrono::seconds(2));

  for (auto &node : all_nodes) {
    node->beginDKG();
  }

  obs.waitForDkgCompletion();

  // Test DKG result
  REQUIRE(obs.checkPublicKeys());

  //Try some threshold signing
  if (num_rounds > 0) {
    for (uint32_t kk = 0; kk < committee_size; ++kk) {
      all_nodes[kk]->enableThresholdSigning(num_rounds);
      all_nodes[kk]->sendSignatureShare();
    }

    obs.waitForSignedMessage();

    // Test signature result
    REQUIRE(obs.checkGroupSignatures(num_rounds));
  }

  pool.stop();

  for (auto &n : all_nodes) {
    n->disconnect();
  }
  std::this_thread::sleep_for(std::chrono::seconds(3));
}

template<class Drb>
void build_no_network() {
  using VerificationKey = typename Drb::VerificationKey;
  using PrivateKey = typename Drb::PrivateKey;
  using Coefficients = std::vector<std::string>;

  struct BeaconManager {
    Drb crypto;
    uint32_t rank;

    BeaconManager(uint32_t cabinet_size, uint32_t threshold, uint32_t manager_rank)
            : crypto{cabinet_size, threshold}, rank{manager_rank} {}

    ~BeaconManager() = default;
  };

  uint32_t cabinet_size = 3;
  uint32_t polynomial_degree = 1;

  std::vector<std::shared_ptr<BeaconManager>> beacon_managers;
  // Name identifiers
  uint32_t my_rank = 0;
  uint32_t honest = 1;
  uint32_t malicious = 2;
  {
    for (uint32_t index = 0; index < cabinet_size; ++index) {
      beacon_managers.emplace_back(new BeaconManager(cabinet_size, polynomial_degree + 1, index));
    }

    std::unordered_map<uint32_t, Coefficients> coefficients;
    std::unordered_map<uint32_t, std::vector<fetch::consensus::pb::PrivateShares>> share_msgs;
    for (auto &manager : beacon_managers) {
      auto coefficients_and_shares = manager->crypto.createCoefficientsAndShares(manager->rank);
      std::vector<std::string> local_coefficients{};
      for (uint32_t ii = 0; ii <= polynomial_degree; ++ii) {
        local_coefficients.push_back(coefficients_and_shares.first.coefficients().coefficients(ii));
      };
      coefficients.insert({manager->rank, local_coefficients});
      share_msgs.insert({manager->rank, coefficients_and_shares.second});
    }

    // Checks
    {
      VerificationKey zero;
      for (uint32_t index = 0; index < cabinet_size; ++index) {
        auto manager = beacon_managers[index];
        std::vector<std::string> local_coefficients = coefficients[index];
        for (uint32_t elem = 0; elem <= polynomial_degree; ++elem) {
          // Coefficients generated should be non-zero
          REQUIRE_FALSE(local_coefficients[elem] == zero.toString());
          for (uint32_t index1 = 0; index1 < cabinet_size; ++index1) {
            if (index1 != index) {
              auto another_manager = beacon_managers[index1];
              std::vector<std::string> local_coefficients1 = coefficients[index1];
              // Coefficients should be different
              REQUIRE_FALSE(local_coefficients == local_coefficients1);
            }
          }
        }
      }
    }

    // Add shares and coefficients passing verification from someone and check that they are entered
    // in correctly
    beacon_managers[my_rank]->crypto.setShare(honest, my_rank, share_msgs[honest][my_rank]);
    for (uint32_t i = 0; i <= polynomial_degree; ++i) {
      beacon_managers[my_rank]->crypto.setCoefficient(honest, i, coefficients[honest][i]);
    }

    // Add shares and coefficients failing verification from malicious party
    std::pair<std::string, std::string> wrong_shares;
    {
      PrivateKey s_i;
      PrivateKey sprime_i;
      s_i.assign(share_msgs[malicious][my_rank].first());
      // Modify one shares
      PrivateKey tmp;
      tmp.random();
      tmp.add(tmp, s_i);
      wrong_shares = {
              tmp.toString(), share_msgs[malicious][my_rank].second()};

      PrivateShares share_msg{wrong_shares.first, wrong_shares.second};

      beacon_managers[my_rank]->crypto.setShare(malicious, my_rank, share_msg.handle());
      for (uint32_t i = 0; i <= polynomial_degree; ++i) {
        REQUIRE(beacon_managers[my_rank]->crypto.setCoefficient(malicious, i, coefficients[malicious][i]));
      }
    }

    std::set<std::string> miners;
    miners.insert("a");
    miners.insert("b");
    miners.insert("c");

    {
      auto complaints = beacon_managers[my_rank]->crypto.computeComplaints(miners, my_rank);
      std::set<std::string> complaints_expected = {"c"};
      REQUIRE(complaints == complaints_expected);
    }

    // Submit false complaints answer
    REQUIRE_FALSE(beacon_managers[my_rank]->crypto.verifyShare(my_rank, malicious, my_rank, wrong_shares.first,
                                                               wrong_shares.second));

    // Submit correct correct complaints answer and check values get replaced
    REQUIRE(beacon_managers[my_rank]->crypto.verifyShare(my_rank, malicious, my_rank,
                                                         share_msgs[malicious][my_rank].first(),
                                                         share_msgs[malicious][my_rank].second()));

    // Distribute correct shares and coefficients amongst everyone else
    {
      std::set<std::string> empty{};
      for (uint32_t index = 1; index < cabinet_size; ++index) {
        for (uint32_t index1 = 0; index1 < cabinet_size; ++index1) {
          if (index1 != index) {
            auto local_all_shares = share_msgs[index1];
            uint32_t shares_index = index;
            if (index > index1) {
              shares_index = shares_index - 1;
            }
            auto local_shares = local_all_shares[shares_index];
            beacon_managers[index]->crypto.setShare(index1, index, local_shares);
            for (uint32_t i = 0; i <= polynomial_degree; ++i) {
              REQUIRE(beacon_managers[index]->crypto.setCoefficient(index1, i, coefficients[index1][i]));
            }
          }
        }
        auto local_complaints = beacon_managers[index]->crypto.computeComplaints(miners, index);
        REQUIRE(local_complaints == empty);
      }
    }


    // Since bad shares have been replaced set qual to be everyone
    std::vector<uint32_t> qual;
    for (auto &manager : beacon_managers) {
      qual.push_back(manager->rank);
    }

    // Check computed secret shares
    for (auto &manager : beacon_managers) {
      manager->crypto.computePrivateKey(manager->rank, qual);
    }

    // Generate qual coefficients for everyone
    std::unordered_map<uint32_t, std::vector<std::string>> qual_coefficients{};
    {
      VerificationKey zero;
      for (auto &manager : beacon_managers) {
        fetch::consensus::pb::Broadcast msg;
        auto *new_qual_coefficients{msg.mutable_coefficients()};
        manager->crypto.computeQualCoefficient(*new_qual_coefficients, manager->rank);
        std::vector<std::string> local_coefficients{};
        for (uint32_t i = 0; i < static_cast<uint32_t>(msg.coefficients().coefficients_size()); ++i) {
          auto coefficient_i = msg.coefficients().coefficients(i);
          REQUIRE_FALSE(coefficient_i == zero.toString());
          local_coefficients.push_back(coefficient_i);
        }
        qual_coefficients.insert({manager->rank, local_coefficients});
      }
    }

    // Add honest qual coefficients
    for (uint32_t i = 0; i < qual_coefficients[honest].size(); ++i) {
      REQUIRE(beacon_managers[my_rank]->crypto.setQualCoefficient(honest, i, qual_coefficients[honest][i]));
    }

    // Verify qual coefficients before malicious submitted coefficients - expect complaint against
    // them
    bool check = beacon_managers[my_rank]->crypto.verifyQualCoefficient(my_rank, honest);
    REQUIRE(check);
    REQUIRE_FALSE(beacon_managers[my_rank]->crypto.verifyQualCoefficient(my_rank, malicious));

    // Add wrong qual coefficients
    for (uint32_t i = 0; i < qual_coefficients[honest].size(); ++i) {
      beacon_managers[my_rank]->crypto.setQualCoefficient(malicious, i, qual_coefficients[honest][i]);
    }

    // Verify qual coefficients and check the complaints
    REQUIRE_FALSE(beacon_managers[my_rank]->crypto.verifyQualCoefficient(my_rank, malicious));

    // Share qual coefficients amongst other nodes
    for (uint32_t index = 1; index < cabinet_size; ++index) {
      for (uint32_t index1 = 0; index1 < cabinet_size; ++index1) {
        if (index1 != index) {
          for (uint32_t i = 0; i < qual_coefficients[honest].size(); ++i) {
            REQUIRE(beacon_managers[index]->crypto.setQualCoefficient(index1, i, qual_coefficients[index1][i]));
          }
          REQUIRE(beacon_managers[index]->crypto.verifyQualCoefficient(index, index1));
        }
      }
    }

    // Invalid qual complaint
    {
      auto result = beacon_managers[my_rank]->crypto.verifyQualComplaint(honest, malicious,
                                                                         share_msgs[honest][malicious -
                                                                                            1].first(),
                                                                         share_msgs[honest][malicious -
                                                                                            1].second());
      REQUIRE(result.first);
      REQUIRE(result.second);
      // Qual complaint which fails first
      auto result2 = beacon_managers[my_rank]->crypto.verifyQualComplaint(malicious, honest,
                                                                          wrong_shares.first, wrong_shares.second);
      REQUIRE_FALSE(result2.first);
      REQUIRE_FALSE(result2.second);
      // Qual complaint which fails second check
      auto result3 = beacon_managers[my_rank]->crypto.verifyQualComplaint(malicious, honest,
                                                                          share_msgs[malicious][honest].first(),
                                                                          share_msgs[malicious][honest].second());
      REQUIRE(result3.first);
      REQUIRE_FALSE(result3.second);
    }

    // Verify invalid reconstruction share
    beacon_managers[my_rank]->crypto.verifyReconstructionShare(honest, malicious, "b", wrong_shares.first,
                                                               wrong_shares.second);
    // Verify valid reconstruction share
    beacon_managers[my_rank]->crypto.verifyReconstructionShare(malicious, honest, "c",
                                                               share_msgs[malicious][honest].first(),
                                                               share_msgs[malicious][honest].second());
    // Duplicate good reconstruction share
    beacon_managers[my_rank]->crypto.verifyReconstructionShare(malicious, honest, "c",
                                                               share_msgs[malicious][honest].first(),
                                                               share_msgs[malicious][honest].second());

    std::unordered_map<std::string, uint32_t> nodes_map;
    nodes_map.insert({"a", 0});
    nodes_map.insert({"b", 1});
    nodes_map.insert({"c", 2});
    // Run reconstruction with not enough shares
    REQUIRE(!(beacon_managers[my_rank]->crypto.runReconstruction(nodes_map)));
    beacon_managers[0]->crypto.newReconstructionShare("c", malicious, my_rank);
    // Run reconstruction with enough shares
    REQUIRE(beacon_managers[my_rank]->crypto.runReconstruction(nodes_map));

    for (auto &manager : beacon_managers) {
      manager->crypto.computePublicKeys(miners, nodes_map);
    }

    // Check outputs agree
    for (uint32_t index = 0; index < cabinet_size; ++index) {
      for (uint32_t index1 = index + 1; index1 < cabinet_size; ++index1) {
        REQUIRE(beacon_managers[index]->crypto.groupPublicKey() ==
                beacon_managers[index1]->crypto.groupPublicKey());
        REQUIRE(beacon_managers[index]->crypto.publicKeyShares() ==
                beacon_managers[index1]->crypto.publicKeyShares());
      }
    }
  }

  // Check threshold signing. First sign message and verify own signature
  {
    std::string message = "Hello";
    std::vector<SignaturesShare> signature_shares;
    std::vector<uint32_t> ranks{0, 1, 2};
    for (auto &manager : beacon_managers) {
      uint32_t own_rank = manager->rank;
      auto temp_result = manager->crypto.getSignatureShare(message, own_rank);
      signature_shares.push_back(temp_result);
      REQUIRE(manager->crypto.addSignatureShare(temp_result.handle(), own_rank));
    }

    // Add invalid signature
    REQUIRE(!(beacon_managers[my_rank]->crypto.addSignatureShare(signature_shares[honest].handle(), malicious)));
    // Add valid signature
    REQUIRE(beacon_managers[my_rank]->crypto.addSignatureShare(signature_shares[honest].handle(), honest));
    REQUIRE(beacon_managers[my_rank]->crypto.addSignatureShare(signature_shares[malicious].handle(), malicious));

    // Check signatures of others with different combinations of signature shares
    bool check_sig = beacon_managers[honest]->crypto.addSignatureShare(signature_shares[my_rank].handle(), my_rank);

    REQUIRE(beacon_managers[malicious]->crypto.addSignatureShare(signature_shares[my_rank].handle(), my_rank));

    //Compute group signatures
    auto sig1 = beacon_managers[my_rank]->crypto.computeGroupSignature(message);
    REQUIRE(check_sig);
    auto sig2 = beacon_managers[honest]->crypto.computeGroupSignature(message);
    REQUIRE(sig1 == sig2);
    auto sig3 = beacon_managers[malicious]->crypto.computeGroupSignature(message);
    REQUIRE(sig1 == sig3);
  }
}