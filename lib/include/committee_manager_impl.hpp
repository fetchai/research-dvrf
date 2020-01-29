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

#include "committee_manager.hpp"
#include "committee_impl.hpp"
#include "rbc.hpp"

namespace fetch {
namespace consensus {

template<class CryptoProtocol>
CommitteeManager<CryptoProtocol>::CommitteeManager(const std::set<std::string> &committee, AbstractDkgNode &node,
                                                   uint32_t threshold, uint8_t committeeId)
        : committeeId_{committeeId}, threshold_{threshold}, node_{node} {
  uint32_t index = 0;
  for (const auto &m : committee) {
    idToIndex_.insert({m, index});
    ++index;
  }
  rbc_ = std::make_unique<RBC>(committee, dynamic_cast<AbstractNode &>(node_), UINT32_MAX, committeeId,
                               preDkgChannelId_);
}

template<class CryptoProtocol>
CommitteeManager<CryptoProtocol>::~CommitteeManager() {
  std::lock_guard<std::mutex> lock(mutex_);
  rbc_.reset();
  committee_.reset();
}

template<class CryptoProtocol>
void CommitteeManager<CryptoProtocol>::enableThresholdSigning(uint32_t t) {
  assert(committee_);
  committee_->enableThresholdSigning(t);
}

template<class CryptoProtocol>
void CommitteeManager<CryptoProtocol>::sendSignatureShare() {
  assert(committee_);
  // Default value for starting the threshold signing is the group pubic key || r = 1
  committee_->sendSignatureShare("initial_seed_" + committee_->groupPublicKey() + std::to_string(1));
}

template<class CryptoProtocol>
void CommitteeManager<CryptoProtocol>::broadcastShares() {
  assert(committee_);
  committee_->broadcastShares();
}

template<class CryptoProtocol>
void CommitteeManager<CryptoProtocol>::onMessage(const fetch::consensus::pb::Direct &msg, const std::string &from) {
  std::unique_lock<std::mutex> lock{mutex_};
  if (msg.has_rbc_msg() and msg.rbc_msg().tag().channel_id() == preDkgChannelId_) {
    if (!rbc_) {
      logger.error("onMessage received pre-dkg rbc message from {} when no rbc", from);
      return;
    }
    auto iter = idToIndex_.find(from);
    if (iter == idToIndex_.end()) {
      return;
    }
    lock.unlock();
    rbc_->onRBC(msg.rbc_msg(), iter->second);
  } else if (msg.has_rbc_msg()) {
    if (!committee_) {
      logger.error("onMessage received RBC message from {} when no committee", from);
      return;
    }
    committee_->onRBC(msg.rbc_msg(), from);
  } else if (msg.has_encrypted_cipher()) {
    uint8_t decrypted_msg[MAX_MESSAGE_LEN + 2];
    size_t size = 0;
    if (node_.decryptCipher(msg.encrypted_cipher(), from, decrypted_msg, size)) {
      fetch::consensus::pb::PrivateShares shares;
      bool check = shares.ParseFromArray(decrypted_msg + 2, static_cast<int>(size));
      assert(check);
      if (!committee_) {
        logger.error("onMessage received dkg shares from {} when no committee", from);
        return;
      }
      committee_->onNewShares(shares, from);
    }
  }
}

template<class CryptoProtocol>
void CommitteeManager<CryptoProtocol>::onSignatureShare(const fetch::consensus::pb::Gossip_SignatureShare &share,
                                                        const std::string &from) {
  if (!committee_) {
    logger.error("onMessage received signature shares from {} when no committee", from);
    return;
  }
  committee_->onSignatureShare(share, from);
}

template<class CryptoProtocol>
bool CommitteeManager<CryptoProtocol>::hasCommittee() const {
  return bool(committee_);
}

template<class CryptoProtocol>
void CommitteeManager<CryptoProtocol>::broadcastCommittee(const std::set<std::string> &new_committee) {
  assert(!committee_);
  committee_ = std::unique_ptr<CommitteeCrypto>(
          new CommitteeCrypto{new_committee, node_, threshold_, committeeId_});
  fetch::consensus::pb::Broadcast broadcast_msg;
  auto *committee = broadcast_msg.mutable_committee();
  for (auto &m : new_committee) {
    committee->add_nodes(m);
  }
  rbc_->broadcast(broadcast_msg);
  std::unique_lock<std::mutex> lock(mutex_);
  committeeSent_ = true;
  receivedCommittee(std::move(lock));
}

template<class CryptoProtocol>
bool CommitteeManager<CryptoProtocol>::checkCommittee(const fetch::consensus::pb::Broadcast_Committee &committee) {
  for (const auto &member : committee.nodes()) {
    if (idToIndex_.find(member) == idToIndex_.end()) {
      return false;
    }
  }
  return true;
}

template<class CryptoProtocol>
void CommitteeManager<CryptoProtocol>::onNewCommittee(const fetch::consensus::pb::Broadcast_Committee &committee,
                                                      const std::string &from) {
  std::unique_lock<std::mutex> lock(mutex_);
  logger.trace("onNewCommittee node {} from {} size {} joined {}", node_.id(), from, committee.nodes_size(),
               joined_.size());
  assert(checkCommittee(committee));
  if (joined_.find(from) == joined_.end()) {
    joined_.insert(from);
    if (joined_.size() == idToIndex_.size() - 1) {
      receivedCommittee(std::move(lock));
    }
  }
}

template<class CryptoProtocol>
void CommitteeManager<CryptoProtocol>::receivedCommittee(std::unique_lock<std::mutex> lock) {
  logger.trace("receivedCommittee node {} joined {} committee_size {}", node_.id(),
               joined_.size(), idToIndex_.size());
  if (committeeSent_ && joined_.size() == idToIndex_.size() - 1) {
    node_.getEventObserver().notifyCommitteeSync(node_.id());
    lock.unlock();
    broadcastShares();
  }
}

template<class CryptoProtocol>
void
CommitteeManager<CryptoProtocol>::onNewCoefficients(const fetch::consensus::pb::Broadcast_Coefficients &coefficients,
                                                    const std::string &from) {
  assert(committee_);
  committee_->onNewCoefficients(coefficients, from);
}

template<class CryptoProtocol>
void CommitteeManager<CryptoProtocol>::onComplaints(const fetch::consensus::pb::Broadcast_Complaints &complaint,
                                                    const std::string &from) {
  assert(committee_);
  committee_->onComplaints(complaint, from);
}

template<class CryptoProtocol>
void CommitteeManager<CryptoProtocol>::onExposedShares(const fetch::consensus::pb::Broadcast_Shares &shares,
                                                       const std::string &from) {
  assert(committee_);
  committee_->onExposedShares(shares, from);
}

template<class CryptoProtocol>
void CommitteeManager<CryptoProtocol>::setDkgOutput(const std::set<std::string> &committee,
                                                    const typename CryptoProtocol::DkgOutput &output) {
  assert(!committee_);
  committee_ = std::unique_ptr<CommitteeCrypto>(
          new CommitteeCrypto{committee, node_, threshold_, committeeId_});
  committee_->setDkgOutput(output);
}

template<class CryptoProtocol>
uint32_t CommitteeManager<CryptoProtocol>::committeeSize() const {
  return static_cast<uint32_t>(idToIndex_.size());
}
}
}
