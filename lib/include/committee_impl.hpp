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

#include "committee.hpp"
#include "node.hpp"
#include "sha3_512.hpp"
#include <chrono>

namespace fetch {
namespace consensus {

template<class CryptoProtocol>
Logger Committee<CryptoProtocol>::logger = fetch::consensus::Logger("committee");

template<class CryptoProtocol>
Committee<CryptoProtocol>::Committee(const std::set<std::string> &committee, fetch::consensus::AbstractDkgNode &node,
                                     uint32_t threshold, uint8_t committeeId)
        : committee_{committee},
          polynomialDegree_{threshold == UINT32_MAX ? uint32_t(committee_.size()) / 2 : threshold - 1},
          committeeId_{committeeId}, crypto_{uint32_t(committee_.size()), threshold}, node_{node},
          rbc_{committee_, dynamic_cast<AbstractNode &>(node)}, complaintsManager_{uint32_t(committee_.size())},
          complaintsAnswerManager_{uint32_t(committee_.size())} {
  assert(committee_.find(node_.id()) != committee_.end());
  uint32_t i = 0;
  for (const auto &member :  committee_) {
    idToIndex_.insert({member, i});
    ++i;
  }
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::broadcastShares() {
  uint32_t rank = idToIndex_[node_.id()];
  auto p = crypto_.createCoefficientsAndShares(rank);
  auto *coefficients = p.first.mutable_coefficients();
  coefficients->set_phase(static_cast<uint64_t>(State::WAITING_FOR_SHARE));
  rbc_.broadcast(p.first);

  auto &shares = p.second;
  size_t j = 0;
  for (auto &miner_j : committee_) {
    size_t real_j = j < rank ? j : j - 1;
    if (j != rank) {
      uint8_t msg_array[MAX_MESSAGE_LEN + 2];
      shares[real_j].SerializeToArray(msg_array + 2, MAX_MESSAGE_LEN);
      node_.sendEncrypted(msg_array, shares[real_j].ByteSizeLong(), miner_j, committeeId_);
    }
    ++j;
  }
  state_.store(State::WAITING_FOR_SHARE);
  receivedCoefficientsAndShares();
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::broadcastComplaints() {
  logger.trace("broadcastComplaints node {}", node_.id());
  std::set<std::string> complaintsLocal = crypto_.computeComplaints(committee_, idToIndex_[node_.id()]);
  fetch::consensus::pb::Broadcast broadcast;
  auto *complaintsMsg = broadcast.mutable_complaints();
  for (auto &c : complaintsLocal) {
    logger.warn("node {} complains against node {}", node_.id(), c);
    complaintsManager_.addComplaintAgainst(c, node_.id());
    complaintsMsg->add_nodes(c);
  }
  rbc_.broadcast(broadcast);
  state_ = State::WAITING_FOR_COMPLAINTS;
  receivedComplaints();
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::broadcastComplaintsAnswer() {
  logger.trace("broadcastComplaintsAnswer node {}", node_.id());
  fetch::consensus::pb::Broadcast msg;
  auto *complaintAnswer = msg.mutable_shares();
  uint32_t rank = idToIndex_[node_.id()];
  for (const auto &reporter : complaintsManager_.complaintsAgainstSelf(node_.id())) {
    crypto_.broadcastShare(*complaintAnswer, reporter, rank, idToIndex_[reporter]);
  }
  complaintAnswer->set_phase(static_cast<uint64_t>(State::WAITING_FOR_COMPLAINT_ANSWERS));
  rbc_.broadcast(msg);
  state_ = State::WAITING_FOR_COMPLAINT_ANSWERS;
  receivedComplaintsAnswer();
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::broadcastQualComplaints() {
  logger.trace("broadcastQualComplaints node {}", node_.id());
  std::set<std::string> complaintsLocal;
  uint32_t rank = idToIndex_[node_.id()];
  uint32_t i = 0;
  const auto miners = committee_;
  auto iq = miners.begin();
  for (const auto &miner : qualified_) {
    while (*iq != miner) {
      ++iq;
      ++i;
    }
    if (i != rank) {
      if (!crypto_.verifyQualCoefficient(rank, i)) {
        complaintsLocal.insert(miner);
        qualComplaintsManager_.addComplaintAgainst(miner);
      }
    }
  }
  fetch::consensus::pb::Broadcast msg;
  auto *expose_shares = msg.mutable_shares();
  for (auto &c : complaintsLocal) {
    logger.trace("node {} exposes shares of node {}", node_.id(), c);
    crypto_.broadcastShare(*expose_shares, c, idToIndex_[c], rank);
  }
  expose_shares->set_phase(static_cast<uint64_t>(State::WAITING_FOR_QUAL_COMPLAINTS));
  rbc_.broadcast(msg);
  state_ = State::WAITING_FOR_QUAL_COMPLAINTS;
  receivedQualComplaints();
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::broadcastReconstructionShares() {
  logger.trace("broadcastReconstructionShares node {}", node_.id());
  fetch::consensus::pb::Broadcast msg;
  auto *exposeShares = msg.mutable_shares();
  uint32_t rank = idToIndex_[node_.id()];
  for (const auto &i : qualComplaintsManager_.complaints()) {
    assert(qualified_.find(i) != qualified_.end());
    uint32_t iIndex{idToIndex_[i]};
    crypto_.newReconstructionShare(i, iIndex, rank);
    crypto_.broadcastShare(*exposeShares, i, iIndex, rank);
  }
  exposeShares->set_phase(static_cast<uint64_t>(State::WAITING_FOR_RECONSTRUCTION_SHARES));
  rbc_.broadcast(msg);
  state_ = State::WAITING_FOR_RECONSTRUCTION_SHARES;
  receivedReconstructionShares();
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::receivedCoefficientsAndShares() {
  std::unique_lock<std::mutex> lock{mutex_};
  logger.trace("receivedCoefficientsAndShares node {} state {} C_ik {} shares {}", node_.id(),
               (state_.load() == State::WAITING_FOR_SHARE),
               coefficientsReceived_.size(), sharesReceived_.size());
  if (!receivedAllCoefAndShares_ and (state_.load() == State::WAITING_FOR_SHARE) and
      (coefficientsReceived_.size() == committee_.size() - 1) and
      (sharesReceived_.size()) == committee_.size() - 1) {
    receivedAllCoefAndShares_.store(true);
    coefficientsReceived_.clear();
    sharesReceived_.clear();
    lock.unlock();
    broadcastComplaints();
  }
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::receivedComplaints() {
  std::unique_lock<std::mutex> lock{mutex_};
  if (!receivedAllComplaints_ and state_ == State::WAITING_FOR_COMPLAINTS and
      complaintsManager_.isFinished(polynomialDegree_ + 1)) {
    complaintsAnswerManager_.init(complaintsManager_.complaints());
    receivedAllComplaints_.store(true);
    lock.unlock();
    broadcastComplaintsAnswer();
  }
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::receivedComplaintsAnswer() {
  std::unique_lock<std::mutex> lock{mutex_};
  if (!receivedAllComplaintsAnswer_ and state_ == State::WAITING_FOR_COMPLAINT_ANSWERS and
      complaintsAnswerManager_.isFinished()) {
    receivedAllComplaintsAnswer_.store(true);
    lock.unlock();
    if (buildQual()) {
      logger.trace("Node {} build qual of size {}", node_.id(), qualified_.size());
      computeSecretShare();
    } else {
      logger.trace("Node {} failed to build qual", node_.id());
    }
    complaintsManager_.clear();
    complaintsAnswerManager_.clear();
  }
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::receivedQualShares() {
  std::unique_lock<std::mutex> lock{mutex_};
  if (!receivedAllQualShares_ and (state_ == State::WAITING_FOR_QUAL_SHARES) and
      (qualCoefficientsReceived_.size() == qualified_.size() - 1)) {
    receivedAllQualShares_.store(true);
    qualCoefficientsReceived_.clear();
    lock.unlock();
    broadcastQualComplaints();
  }
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::receivedQualComplaints() {
  std::unique_lock<std::mutex> lock{mutex_};
  if (!receivedAllQualComplaints_ and (state_ == State::WAITING_FOR_QUAL_COMPLAINTS)
      and (qualComplaintsManager_.isFinished(qualified_.size()))) {
    receivedAllQualComplaints_.store(true);
    size_t size = qualComplaintsManager_.complaintsSize();
    if (size > polynomialDegree_) {
      logger.error("Node {} protocol has failed: complaints size {}", node_.id(), size);
      return;
    } else if (qualComplaintsManager_.complaintsFind(node_.id())) {
      logger.warn("Node {} is in qual complaints", node_.id());
      computePublicKeys();
      return;
    }
    assert(qualified_.find(node_.id()) != qualified_.end());
    lock.unlock();
    broadcastReconstructionShares();
  }
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::receivedReconstructionShares() {
  std::unique_lock<std::mutex> lock{mutex_};
  if (!receivedAllReconstructionShares_ and state_ == State::WAITING_FOR_RECONSTRUCTION_SHARES and
      reconstructionSharesReceived_.size() == (qualified_.size() - qualComplaintsManager_.complaintsSize() - 1)) {
    receivedAllReconstructionShares_.store(true);
    reconstructionSharesReceived_.clear();
    lock.unlock();
    if (!runReconstruction()) {
      logger.error("Node {} DKG failed due to reconstruction failure", node_.id());
    } else {
      computePublicKeys();
      qualComplaintsManager_.clear();
    }
  }
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::receivedSignatureShares(const std::string &message) {
  std::unique_lock<std::mutex> lock{mutex_};
  logger.trace("receivedSignatureShares node {} msg {} nb {} ", node_.id(), message,
               crypto_.numSignatureShares(message));
  if (crypto_.isFinished(message)) {
    auto sig = crypto_.computeGroupSignature(message);
    assert(!sig.empty());
    fetch::consensus::SHA3_512 sigHash{sig};
    logger.info("Node {} round {} random value {}", idToIndex_[node_.id()], thresholdSigningComputed_, sigHash.toString());
    lock.unlock();
    node_.getEventObserver().notifyGroupSignature(message, sig);
    if (thresholdSigningComputed_ < thresholdSigningEnabled_) {
      ++thresholdSigningComputed_;
      sendSignatureShare(sigHash.toString() + std::to_string(thresholdSigningComputed_));
    } else {
      auto end = std::chrono::high_resolution_clock::now();
      node_.getEventObserver().notifySignedMessage(node_.id(), end);
    }
  }
}

template<class CryptoProtocol>
void
Committee<CryptoProtocol>::onNewShares(const fetch::consensus::pb::PrivateShares &shares, const std::string &from) {
  logger.trace("onNewShares node {} from {}", node_.id(), from);
  if (sharesReceived_.find(from) == sharesReceived_.end()) {
    sharesReceived_.insert(from);
    crypto_.setShare(idToIndex_[from], idToIndex_[node_.id()], shares);
    receivedCoefficientsAndShares();
  }
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::onRBC(const fetch::consensus::pb::Direct_RBC &msg, const std::string &from) {
  if (idToIndex_.find(from) == idToIndex_.end()) {
    return;
  }
  rbc_.onRBC(msg, idToIndex_[from]);
}

template<class CryptoProtocol>
void
Committee<CryptoProtocol>::onExposedShares(const fetch::consensus::pb::Broadcast_Shares &shares,
                                           const std::string &from) {
  uint64_t phase{shares.phase()};
  if (phase == static_cast<uint64_t>(State::WAITING_FOR_COMPLAINT_ANSWERS)) {
    logger.trace("complaint answer {} from {}", node_.id(), from);
    onComplaintsAnswer(shares, from);
  } else if (phase == static_cast<uint64_t>(State::WAITING_FOR_QUAL_COMPLAINTS)) {
    logger.trace("qual complaint {} from {}", node_.id(), from);
    onQualComplaints(shares, from);
  } else if (phase == static_cast<uint64_t>(State::WAITING_FOR_RECONSTRUCTION_SHARES)) {
    logger.trace("Reconstruction shares {} from {}", node_.id(), from);
    onReconstructionShares(shares, from);
  }
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::onNewCoefficients(const fetch::consensus::pb::Broadcast_Coefficients &coefficients,
                                                  const std::string &from) {
  logger.trace("onNewCoefficients node {} from {} phase 1 {}", node_.id(), from,
               coefficients.phase() == static_cast<uint64_t>(State::WAITING_FOR_SHARE));
  uint32_t fromIndex{idToIndex_[from]};
  if (coefficients.phase() == static_cast<uint64_t>(State::WAITING_FOR_SHARE)) {
    if ((uint32_t) coefficients.coefficients().size() != polynomialDegree_ + 1) {
      logger.warn("Node {} received coefficients of wrong size from {}", idToIndex_[node_.id()], fromIndex);
      return;
    }
    if (coefficientsReceived_.find(from) != coefficientsReceived_.end()) {
      return;
    }

    for (uint32_t ii = 0; ii <= polynomialDegree_; ++ii) {
      if (!crypto_.setCoefficient(fromIndex, ii, coefficients.coefficients(ii))) {
        logger.warn("Node {} received invalid coefficients from {}", idToIndex_[node_.id()], fromIndex);
        return;
      }
    }
    coefficientsReceived_.insert(from);
    receivedCoefficientsAndShares();
  } else if (coefficients.phase() == static_cast<uint64_t>(State::WAITING_FOR_QUAL_SHARES)) {

    if (qualified_.empty()) {
      qualCoefficientsQueue_.insert({from, coefficients});
      return;
    }

    processQualCoefficients(coefficients, from);
  }
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::onComplaints(const fetch::consensus::pb::Broadcast_Complaints &complaint,
                                             const std::string &from) {
  complaintsManager_.addComplaintsFrom(complaint, from, committee_);
  receivedComplaints();
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::onComplaintsAnswer(const fetch::consensus::pb::Broadcast_Shares &answer,
                                                   const std::string &from) {
  uint32_t fromIndex{idToIndex_[from]};
  uint32_t rank{idToIndex_[node_.id()]};
  if (complaintsAnswerManager_.addAnswerFrom(from)) {
    checkComplaintAnswer(answer, from, fromIndex, rank);
  }
  receivedComplaintsAnswer();
}

template<class CryptoProtocol>
void
Committee<CryptoProtocol>::onQualComplaints(const fetch::consensus::pb::Broadcast_Shares &shares,
                                            const std::string &from) {
  assert(!qualified_.empty());
  // Return if the sender not in qual
  if (qualified_.find(from) == qualified_.end()) {
    return;
  }

  // If have already received complaints from sender, return
  if (!qualComplaintsManager_.addQualComplaintsFrom(from)) {
    return;
  }

  logger.trace("onQualComplaints node {} from {}", node_.id(), from);
  // If not all fields are complete we complain against the sender
  if (shares.first_size() != shares.second_size() or shares.first_size() != shares.reporter_size()) {
    qualComplaintsManager_.addComplaintAgainst(from);
  } else {
    for (auto ii = 0; ii < shares.first_size(); ++ii) {
      //Check person who's shares are being exposed is not in qual then don't bother with checks
      if (qualified_.find(shares.reporter(ii)) != qualified_.end()) {
        auto p = crypto_.verifyQualComplaint(idToIndex_[shares.reporter(ii)], idToIndex_[from], shares.first(ii),
                                             shares.second(ii));
        if (!p.first) {
          qualComplaintsManager_.addComplaintAgainst(from);
        }
        if (!p.second) {
          qualComplaintsManager_.addComplaintAgainst(shares.reporter(ii));
        } else {
          qualComplaintsManager_.addComplaintAgainst(from);
        }
      }
    }
  }
  receivedQualComplaints();
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::onReconstructionShares(const fetch::consensus::pb::Broadcast_Shares &shares,
                                                       const std::string &from) {
  if (reconstructionSharesReceived_.find(from) != reconstructionSharesReceived_.end()) {
    return;
  }
  //Return if the sender is in complaints, or not in qual
  if (qualComplaintsManager_.complaintsFind(from) or qualified_.find(from) == qualified_.end()) {
    return;
  }
  for (auto ii = 0; ii < shares.first_size(); ++ii) {
    const std::string reporter = shares.reporter(ii);
    if (qualified_.find(reporter) != qualified_.end()) {
      uint32_t victim_index{idToIndex_[reporter]};
      crypto_.verifyReconstructionShare(victim_index, idToIndex_[from], reporter, shares.first(ii), shares.second(ii));
    }
  }
  reconstructionSharesReceived_.insert(from);
  receivedReconstructionShares();
}

template<class CryptoProtocol>
void
Committee<CryptoProtocol>::onSignatureShare(const fetch::consensus::pb::Gossip_SignatureShare &share,
                                            const std::string &from) {
  if (qualified_.find(from) == qualified_.end() or qualComplaintsManager_.complaintsFind(from) or
      crypto_.groupSignatureCompleted(share.message())) {
    return;
  }
  if (groupPublicKey().empty()) {
    logger.trace("Node {} received signature share too early");
    signatureShareQueue_.insert({from, share});
    return;
  }
  if (crypto_.addSignatureShare(share, idToIndex_[from])) {
    logger.trace("Node {} verify share of message {} from {}", node_.id(), share.message(), from);
  } else {
    logger.error("Node {} verify share of message {} from {} failed", node_.id(), share.message(), from);
  }
  receivedSignatureShares(share.message());
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::checkComplaintAnswer(const fetch::consensus::pb::Broadcast_Shares &answer,
                                                     const std::string &from,
                                                     uint32_t from_index, uint32_t rank) {

  // If a fields are not all complete we complain against the sender and do not process
  if (answer.first_size() != answer.second_size() or answer.first_size() != answer.reporter_size()) {
    complaintsAnswerManager_.addComplaintAgainst(from);
    return;
  }

  // If number of answers does not match number of complaints return
  if (complaintsManager_.complaintsCount(from) != static_cast<uint32_t>(answer.first_size())) {
    complaintsAnswerManager_.addComplaintAgainst(from);
    return;
  }

  auto num_complaints = complaintsManager_.complaintsCount(from);
  for (auto ii = 0; ii < answer.first_size(); ++ii) {
    if (committee_.find(answer.reporter(ii)) == committee_.end()) {
      logger.error("node {} verification for node {} complaint answer failed. Non-existent address in answer.",
                   node_.id(), from_index);
      complaintsAnswerManager_.addComplaintAgainst(from);
      continue;
    }

    if (complaintsManager_.findComplaint(from, answer.reporter(ii))) {
      if (crypto_.verifyShare(idToIndex_[answer.reporter(ii)], from_index, rank, answer.first(ii),
                              answer.second(ii))) {
        logger.trace("node {} verification for node {} complaint answer succeeded", node_.id(), from_index);
      } else {
        logger.error("node {} verification for node {} complaint answer failed", node_.id(), from_index);
        complaintsAnswerManager_.addComplaintAgainst(from);
      }
      --num_complaints;
    }
  }
  // If not enough answers are sent for number of complaints against a node then add a complaint a against it
  // for each missing answer
  if (num_complaints != 0) {
    complaintsAnswerManager_.addComplaintAgainst(from);
  }
}

template<class CryptoProtocol>
bool Committee<CryptoProtocol>::buildQual() {
  //Altogether, complaints consists of
  // 1. Nodes who did not send, sent too many or sent duplicate complaints
  // 2. Nodes which received over t complaints
  // 3. Nodes who did not complaint answers
  // 4. Complaint answers which were false
  logger.trace("buildQual node {}", node_.id());
  qualified_ = complaintsAnswerManager_.buildQual(committee_);
  if (qualified_.find(node_.id()) == qualified_.end() or qualified_.size() <= polynomialDegree_) {
    if (qualified_.find(node_.id()) == qualified_.end()) {
      logger.error("Node {} build qual failed as not in qual", node_.id());
    } else {
      logger.error("Node {} build qual failed as size {} less than threshold {}", node_.id(), qualified_.size(),
                   polynomialDegree_ + 1);
    }
    return false;
  }
  return true;
}

template<class CryptoProtocol>
void
Committee<CryptoProtocol>::processQualCoefficients(const fetch::consensus::pb::Broadcast_Coefficients &coefficients,
                                                   const std::string &from) {
  assert(!qualified_.empty());
  if (qualified_.find(from) == qualified_.end()) {
    return;
  }
  if (qualCoefficientsReceived_.find(from) != qualCoefficientsReceived_.end()) {
    return;
  }

  uint32_t fromIndex{idToIndex_[from]};
  // Check for coefficients being correct size is in setQualCoefficients of crypto
  for (uint32_t ii = 0; ii < static_cast<uint32_t>(coefficients.coefficients_size()); ++ii) {
    if (!crypto_.setQualCoefficient(fromIndex, ii, coefficients.coefficients(ii))) {
      logger.warn("Node {} received invalid qual coefficients from {}", idToIndex_[node_.id()], fromIndex);
      return;
    }
  }
  qualCoefficientsReceived_.insert(from);
  receivedQualShares();
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::computeSecretShare() {
  logger.trace("Node {} computeSecretShare", node_.id());

  std::vector<uint32_t> quals;
  for (auto const &iq : qualified_) {
    quals.push_back(idToIndex_[iq]);
  }
  uint32_t rank = idToIndex_[node_.id()];
  crypto_.computePrivateKey(rank, quals);

  fetch::consensus::pb::Broadcast msg;
  auto *coefficients{msg.mutable_coefficients()};
  coefficients->set_phase(static_cast<uint64_t>(State::WAITING_FOR_QUAL_SHARES));
  crypto_.computeQualCoefficient(*coefficients, rank);
  rbc_.broadcast(msg);
  state_ = State::WAITING_FOR_QUAL_SHARES;
  for (const auto &coeff : qualCoefficientsQueue_) {
    processQualCoefficients(coeff.second, coeff.first);
  }
  receivedQualShares();
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::computePublicKeys_() {
  logger.info("Node {} compute public keys", node_.id());
  auto start = std::chrono::high_resolution_clock::now();
  crypto_.computePublicKeys(qualified_, idToIndex_);
  auto end = std::chrono::high_resolution_clock::now();
  node_.getEventObserver().notifyDKGCompleted(node_.id(), (end - start), crypto_.groupPublicKey());
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::computePublicKeys() {
  ThreadPool::getInstance().enqueue([this]() { computePublicKeys_(); });
}

template<class CryptoProtocol>
bool Committee<CryptoProtocol>::runReconstruction() {
  logger.trace("Node {} runReconstruction", node_.id());
  return crypto_.runReconstruction(idToIndex_);
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::sendSignatureShare(const std::string &message) {
  auto start_time = std::chrono::high_resolution_clock::now();
  logger.trace("Node {} sendSignatureShare msg {}", node_.id(), message);
  uint32_t index = idToIndex_[node_.id()];
  auto sig_msg = crypto_.getSignatureShare(message, index);
  node_.sendGossip(Gossip{sig_msg});
  node_.getEventObserver().notifyBroadcastSignature(node_.id(), start_time);

  // Process old messages if have them
  for (const auto share : signatureShareQueue_) {
    onSignatureShare(share.second, share.first);
  }
}

template<class CryptoProtocol>
std::size_t Committee<CryptoProtocol>::size() const {
  return committee_.size();
}

template<class CryptoProtocol>
std::size_t Committee<CryptoProtocol>::threshold() const {
  return polynomialDegree_ + 1;
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::enableThresholdSigning(uint32_t t) {
  thresholdSigningEnabled_.store(t);
}

template<class CryptoProtocol>
void Committee<CryptoProtocol>::setDkgOutput(const typename CryptoProtocol::DkgOutput &output) {
  qualified_ = committee_;
  crypto_.setDkgOutput(output);
}

template<class CryptoProtocol>
std::string Committee<CryptoProtocol>::groupPublicKey() const {
  return crypto_.groupPublicKey();
}
}
}
