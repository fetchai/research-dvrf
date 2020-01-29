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

#include "bls_dkg.hpp"

namespace fetch {
namespace consensus {

template<class CryptoType>
class DfinityDvrf : public BlsDkg<CryptoType> {
public:
  using MessagePayload = typename BlsDkg<CryptoType>::MessagePayload;
  using Signature = typename BlsDkg<CryptoType>::Signature;
  using PrivateKey = typename BlsDkg<CryptoType>::PrivateKey;
  using VerificationKey = typename BlsDkg<CryptoType>::VerificationKey;
  using Pairing = typename CryptoType::Pairing;

  DfinityDvrf(uint32_t committeeSize, uint32_t threshold) : BlsDkg<CryptoType>{committeeSize, threshold} {}

  virtual ~DfinityDvrf() = default;

  /**
 * Verifies a signature
 *
 * @param y The public key (can be the group public key, or public key share)
 * @param message Message that was signed
 * @param sign Signature to be verified
 * @param G Generator used in DKG
 * @return
 */
  static bool
  verify(const VerificationKey &y, const MessagePayload &message, const Signature &sign, const VerificationKey &G) {
    Pairing e1, e2;
    Signature PH;
    PH.hashAndMap(message);

    e1.map(sign, G);
    e2.map(PH, y);
    return e1 == e2;
  }

  SignaturesShare getSignatureShare(const MessagePayload &message, uint32_t rank) override {
    std::lock_guard<std::mutex> lock(this->mutex_);
    assert(!message.empty());
    auto myShare{this->sign(message, this->privateKey_)};
    this->groupSignatureManager_.addSignatureShares(message, {rank, myShare});
    //Sanity check: verify own signature
    assert(verify(this->publicKeyShares_[rank], message, myShare, this->G));
    return SignaturesShare{message, myShare.toString()};
  }

  bool addSignatureShare(const fetch::consensus::pb::Gossip_SignatureShare &share_msg, uint32_t minerIndex) override {
    assert(!share_msg.has_share_pi());
    assert(!share_msg.has_share_pi2());
    std::lock_guard<std::mutex> lock(this->mutex_);
    Signature share_j;
    if (share_j.assign(share_msg.share_sig()) &&
        verify(this->publicKeyShares_[minerIndex], share_msg.message(), share_j, this->G)) {
      this->groupSignatureManager_.addSignatureShares(share_msg.message(), {minerIndex, share_j});
      return true;
    }
    return false;
  }
};

}
}