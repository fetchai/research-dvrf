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

template<class Crypto>
class DdhDvrf : public BlsDkg<Crypto> {
public:
  using MessagePayload = typename BlsDkg<Crypto>::MessagePayload;
  using Signature = typename BlsDkg<Crypto>::Signature;
  using PrivateKey = typename BlsDkg<Crypto>::PrivateKey;
  using VerificationKey = typename BlsDkg<Crypto>::VerificationKey;
  using Proof = typename Crypto::Proof;

  DdhDvrf(uint32_t committeeSize, uint32_t threshold) : BlsDkg<Crypto>{committeeSize, threshold} {}

  virtual ~DdhDvrf() = default;

  static Proof proof(const VerificationKey &G, const MessagePayload &message, const VerificationKey &y,
                     const Signature &sig,
                     const PrivateKey &x) {
    Signature PH;
    PH.hashAndMap(message);

    PrivateKey r;
    r.random();
    VerificationKey com1, com2;
    com1.mult(G, r);
    com2.mult(PH, r);

    Proof pi;
    pi.first.setHashOf(G, PH, y, sig, com1, com2);
    PrivateKey localVar;
    localVar.mult(x, pi.first);
    pi.second.add(r, localVar);
    return pi;
  }

  /**
 * Verifies a signature
 *
 * @param y The public key share
 * @param message Message that was signed
 * @param sign Signature to be verified
 * @param G Generator used in DKG
 * @return
 */
  static bool verify(const VerificationKey &y, const MessagePayload &message, const Signature &sign,
                     const VerificationKey &G,
                     const Proof &proof) {
    Signature PH;
    PH.hashAndMap(message);

    VerificationKey tmp, c1, c2;
    PrivateKey tmps;
    tmps.negate(proof.first);
    c1.mult(G, proof.second);
    tmp.mult(y, tmps);
    c1.add(c1, tmp);
    c2.mult(PH, proof.second);
    tmp.mult(sign, tmps);
    c2.add(c2, tmp);

    PrivateKey ch_cmp;
    ch_cmp.setHashOf(G, PH, y, sign, c1, c2);

    return proof.first == ch_cmp;
  }

  SignaturesShare getSignatureShare(const MessagePayload &message, uint32_t rank) override {
    std::lock_guard<std::mutex> lock(this->mutex_);
    auto mySign = this->sign(message, this->privateKey_);
    auto myPI = proof(this->G, message, this->publicKeyShares_[rank], mySign, this->privateKey_);

    //Sanity check: verify own signature
    this->groupSignatureManager_.addSignatureShares(message, {rank, mySign});
    assert(verify(this->publicKeyShares_[rank], message, mySign, this->G, myPI));
    auto piStr = std::make_pair(myPI.first.toString(), myPI.second.toString());
    return SignaturesShare{message, mySign.toString(), piStr};
  }

  bool addSignatureShare(const fetch::consensus::pb::Gossip_SignatureShare &share_msg, uint32_t minerIndex) override {
    assert(share_msg.has_share_pi());
    assert(share_msg.has_share_pi2());
    std::lock_guard<std::mutex> lock(this->mutex_);
    Signature sig;
    Proof pi;

    if (sig.assign(share_msg.share_sig()) && pi.first.assign(share_msg.share_pi()) &&
        pi.second.assign(share_msg.share_pi2()) &&
        verify(this->publicKeyShares_[minerIndex], share_msg.message(), sig, this->G, pi)) {
      this->groupSignatureManager_.addSignatureShares(share_msg.message(), {minerIndex, sig});
      return true;
    } else {
      return false;
    }
  }
};

}
}
