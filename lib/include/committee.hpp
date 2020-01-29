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

#include "complaint_managers.hpp"
#include "logger.hpp"
#include "rbc.hpp"
#include "sha256.hpp"
#include "consensus.pb.h"
#include <set>
#include <iostream>
#include <atomic>
#include <unordered_set>
#include "threadpool.hpp"

namespace fetch {
namespace consensus {
class AbstractDkgNode;

/**
 * Manages the state machine for the DKG, which is driven by the receipt of messages
 * from DKG members.
 *
 * @tparam CryptoType Crypto class used in DKG and threshold signing
 */
template<class CryptoProtocol>
class Committee {
  enum class State : uint8_t {
    INITIAL,
    WAITING_FOR_SHARE,
    WAITING_FOR_COMPLAINTS,
    WAITING_FOR_COMPLAINT_ANSWERS,
    WAITING_FOR_QUAL_SHARES,
    WAITING_FOR_QUAL_COMPLAINTS,
    WAITING_FOR_RECONSTRUCTION_SHARES
  };
  static fetch::consensus::Logger logger;

  const std::set<std::string> committee_; ///< Set of all member ids in DKG
  uint32_t polynomialDegree_; ///< Polynomial degree, which sets threshold for group signature
  uint8_t committeeId_; ///< Id for this committee
  CryptoProtocol crypto_; ///< Crypto type
  AbstractDkgNode &node_; ///< Node for handling of messages
  RBC rbc_; ///< Reliable broadcast channel
  std::unordered_map<std::string, uint32_t> idToIndex_{}; ///< Map from member id to index in DKG
  std::atomic<State> state_{State::INITIAL};
  mutable std::mutex mutex_;

  /// DKG complaint managers
  /// @{
  ComplaintsManager complaintsManager_;
  ComplaintsAnswerManager complaintsAnswerManager_;
  QualComplaintsManager qualComplaintsManager_;
  /// @}

  /// State transition record
  /// @{
  std::atomic<bool> receivedAllCoefAndShares_{false};
  std::atomic<bool> receivedAllComplaints_{false};
  std::atomic<bool> receivedAllComplaintsAnswer_{false};
  std::atomic<bool> receivedAllQualShares_{false};
  std::atomic<bool> receivedAllQualComplaints_{false};
  std::atomic<bool> receivedAllReconstructionShares_{false};
  /// @}

  /// State transition counters
  /// @{
  std::unordered_set<std::string> sharesReceived_;
  std::unordered_set<std::string> coefficientsReceived_;
  std::unordered_set<std::string> qualCoefficientsReceived_;
  std::unordered_set<std::string> reconstructionSharesReceived_;
  /// @}

  std::set<std::string> qualified_; ///< Qualified members in DKG
  std::unordered_map<std::string, fetch::consensus::pb::Broadcast_Coefficients> qualCoefficientsQueue_;

  std::atomic<uint32_t> thresholdSigningComputed_{1}; ///< Threshold signatures computed
  std::atomic<uint32_t> thresholdSigningEnabled_{0}; ///< Threshold signatures to compute
  std::unordered_map<std::string, fetch::consensus::pb::Gossip_SignatureShare> signatureShareQueue_;

  /// Broadcasts at each DKG stage
  /// @{
  void broadcastComplaints();
  void broadcastComplaintsAnswer();
  void broadcastQualComplaints();
  void broadcastReconstructionShares();
  /// @}

  /// State transition triggers
  /// @{
  void receivedCoefficientsAndShares();
  void receivedComplaints();
  void receivedComplaintsAnswer();
  void receivedQualShares();
  void receivedQualComplaints();
  void receivedReconstructionShares();
  void receivedSignatureShares(const std::string &message);
  /// @}

  /// Helper functions
  /// @{
  void checkComplaintAnswer(const fetch::consensus::pb::Broadcast_Shares &answer, const std::string &from,
                            uint32_t from_index, uint32_t rank);
  bool buildQual();
  void
  processQualCoefficients(const fetch::consensus::pb::Broadcast_Coefficients &coefficients, const std::string &from);
  void computeSecretShare();
  void computePublicKeys_();
  void computePublicKeys();
  bool runReconstruction();
  /// @}

  /// Message handlers
  /// @{
  void onComplaintsAnswer(const fetch::consensus::pb::Broadcast_Shares &answer, const std::string &from);
  void onQualComplaints(const fetch::consensus::pb::Broadcast_Shares &shares, const std::string &from);
  void onReconstructionShares(const fetch::consensus::pb::Broadcast_Shares &shares, const std::string &from);
  /// @}

public:
  Committee(const std::set<std::string> &committee, fetch::consensus::AbstractDkgNode &node,
            uint32_t threshold = UINT32_MAX, uint8_t committeeId = 0);

  void broadcastShares();

  /// Message handlers
  /// @{
  void onNewShares(const fetch::consensus::pb::PrivateShares &shares, const std::string &from_);
  void onNewCoefficients(const fetch::consensus::pb::Broadcast_Coefficients &coefficients,
                         const std::string &from);
  void onRBC(const fetch::consensus::pb::Direct_RBC &msg, const std::string &from);
  void onComplaints(const fetch::consensus::pb::Broadcast_Complaints &complaint, const std::string &from);
  void onExposedShares(const fetch::consensus::pb::Broadcast_Shares &shares, const std::string &from);
  void onSignatureShare(const fetch::consensus::pb::Gossip_SignatureShare &share, const std::string &from);
  /// @}

  /// Threshold signing
  /// @{
  void enableThresholdSigning(uint32_t t);
  void sendSignatureShare(const std::string &message);
  /// @}

  void setDkgOutput(const typename CryptoProtocol::DkgOutput &output);

  std::size_t size() const;
  std::size_t threshold() const;
  std::string groupPublicKey() const;
};
} //consensus
} //fetch
