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

#include "base_dkg.hpp"

namespace fetch {
namespace consensus {

template<class CryptoType>
class BlsDkg : public BaseDkg<CryptoType, typename CryptoType::GroupPublicKey> {
public:
  using Base = BaseDkg<CryptoType, typename CryptoType::GroupPublicKey>;
  using PrivateKey = typename CryptoType::PrivateKey;
  using Signature = typename CryptoType::Signature;
  using GroupPublicKey = typename CryptoType::GroupPublicKey;
  using VerificationKey = typename CryptoType::GroupPublicKey;
  using MessagePayload = std::string;

  BlsDkg(uint32_t committeeSize, uint32_t threshold) : BaseDkg<CryptoType, typename CryptoType::GroupPublicKey>{
          committeeSize, threshold} {
    g__a_i_.resize(this->polynomialDegree_ + 1);
  }

  virtual ~BlsDkg() = default;

  /**
 * Generate coefficients and secret shares to be broadcast and sent directly to each member,
 * respectively
 * @param rank Our index
 * @return pair of broadcast and vector of direct messages to be sent
 */
  std::pair<fetch::consensus::pb::Broadcast, std::vector<fetch::consensus::pb::PrivateShares>>
  createCoefficientsAndShares(uint32_t rank) override {
    std::vector<PrivateKey> a_i(this->polynomialDegree_ + 1), b_i(this->polynomialDegree_ + 1);
    for (size_t k = 0; k <= this->polynomialDegree_; k++) {
      a_i[k].random();
      b_i[k].random();
    }
    return std::make_pair(createCoefficients(a_i, b_i, rank), this->createShares(a_i, b_i, rank));
  }

  /**
 * Fill a coefficients message with our qual coefficients to be broadcasted
 *
 * @param coefs Coefficients message
 * @param rank Our index
 */
  void computeQualCoefficient(fetch::consensus::pb::Broadcast_Coefficients &coefs, uint32_t rank) override {
    for (size_t k = 0; k <= this->polynomialDegree_; k++) {
      this->A_ik_[rank][k] = g__a_i_[k];
      coefs.add_coefficients(this->A_ik_[rank][k].toString());
    }
  }

  /**
 * Insert qual coefficients from other qualified members
 *
 * @param from Index of sender
 * @param i Index in coefficients vector
 * @param coef String value of the coefficient at i
 * @return bool indicating whether value passes deserialisation
 */
  bool setQualCoefficient(uint32_t from, uint32_t i, const std::string &coef) override {
    if (i > this->polynomialDegree_) {
      return false;
    }
    if (this->A_ik_[from][i].isZero()) {
      return this->A_ik_[from][i].assign(coef);
    }
    return false;
  }

  /**
 * Checks qual coefficients received from qualified members
 *
 * @param rank Our index
 * @param i Index in vector of coefficient
 * @return Whether coefficient passed verification
 */
  bool verifyQualCoefficient(uint32_t rank, uint32_t i) const override {
    if (!this->A_ik_[i][0].isZero()) {
      VerificationKey rhs, lhs;
      lhs = this->g__s_ij_[i][rank];
      rhs = this->computeRHS(rank, this->A_ik_[i]);
      return lhs == rhs;
    }
    return false;
  }

  /**
 * Verify whether a qual complaint was genuine from broadcasted secret shares
 *
 * @param nodeIndex Index of node being complained against
 * @param fromIndex Index of complaint filer
 * @param first First secret share as string
 * @param second Second secret share as string
 * @return Pair of bools whether the shares pass verification with respect to initial and
 * qual coefficients, respectively
 */
  std::pair<bool, bool> verifyQualComplaint(uint32_t nodeIndex, uint32_t fromIndex, const std::string &first,
                                            const std::string &second) override {
    std::pair<bool, bool> res{false, false};
    VerificationKey lhs, rhs;
    PrivateKey s, sprime;

    if (s.assign(first) && sprime.assign(second)) {
      lhs = this->computeLHS(this->G, this->H, s, sprime);
      rhs = this->computeRHS(fromIndex, this->C_ik_[nodeIndex]);
      res.first = lhs == rhs;
      lhs.mult(this->G, s);
      rhs = this->computeRHS(fromIndex, this->A_ik_[nodeIndex]);
      res.second = lhs == rhs;
    }
    return res;
  }

  /**
 * Run polynomial interpolation on the exposed secret shares of other cabinet members to
 * recontruct their random polynomials
 *
 * @return Bool for whether reconstruction from shares was successful
 */
  bool runReconstruction(const std::unordered_map<std::string, uint32_t> &nodesMap) override {
    std::lock_guard<std::mutex> lock(this->mutex_);
    assert(this->committeeSize_ == nodesMap.size());
    std::vector<std::vector<PrivateKey>> a_ik;
    this->init(a_ik, this->committeeSize_, this->polynomialDegree_ + 1);
    for (const auto &in : this->reconstructionShares_) {
      std::set<std::size_t> parties{in.second.first};
      std::vector<PrivateKey> shares{in.second.second};
      if (parties.size() <= this->polynomialDegree_) {
        // Do not have enough good shares to be able to do reconstruction
        return false;
      }

      auto iter = nodesMap.find(in.first);
      assert(iter != nodesMap.end());
      uint32_t victimIndex{iter->second};
      std::vector<PrivateKey> points, shares_f;
      for (const auto &index : parties) {
        points.emplace_back(index + 1);  // adjust index in computation
        shares_f.push_back(shares[index]);
      }
      a_ik[victimIndex] = this->interpolatePolynom(points, shares_f);

      for (size_t k = 0; k <= this->polynomialDegree_; k++) {
        this->A_ik_[victimIndex][k].mult(this->G, a_ik[victimIndex][k]);
      }
    }
    return true;
  }

  /**
 * Compute group public key and individual public key shares
 */
  void
  computePublicKeys(const std::set<std::string> &qual,
                    const std::unordered_map<std::string, uint32_t> &nodesMap) override {
    std::lock_guard<std::mutex> lock(this->mutex_);
    std::vector<VerificationKey> y_i;
    y_i.resize(this->committeeSize_);
    for (const auto &iq : qual) {
      auto iter = nodesMap.find(iq);
      assert(iter != nodesMap.end());
      uint32_t it{iter->second};
      y_i[it] = this->A_ik_[it][0];
    }
    this->groupPublicKey_.setZero();
    for (const auto &iq : qual) {
      auto iter = nodesMap.find(iq);
      assert(iter != nodesMap.end());
      uint32_t it{iter->second};
      this->groupPublicKey_.add(this->groupPublicKey_, y_i[it]);
    }

    // Compute group public keys
    /*
    for (const auto &jq : qual) {
      auto iter_j = nodesMap.find(jq);
      assert(iter_j != nodesMap.end());
      uint32_t jt{iter_j->second};
      for (const auto &iq : qual) {
        auto iter_i = nodesMap.find(iq);
        assert(iter_i != nodesMap.end());
        uint32_t it{iter_i->second};
        this->publicKeyShares_[jt].add(this->publicKeyShares_[jt], this->A_ik_[it][0]);
        this->updateRHS(jt, this->publicKeyShares_[jt], this->A_ik_[it]);
      }
    }*/

      std::vector<VerificationKey> vCoeff;
      for (size_t k = 0; k <= this->polynomialDegree_; k++) {
          VerificationKey tmpV;
          tmpV.setZero();
          for (const auto &jq : qual) {
              auto iter_j = nodesMap.find(jq);
              assert(iter_j != nodesMap.end());
              uint32_t jt{iter_j->second};
              tmpV.add(tmpV, this->A_ik_[jt][k]);
          }
          vCoeff.push_back(tmpV);
      }

      for (const auto &jq : qual) {
          auto iter_j = nodesMap.find(jq);
          assert(iter_j != nodesMap.end());
          uint32_t jt{iter_j->second};
          this->publicKeyShares_[jt].add(this->publicKeyShares_[jt], vCoeff[0]);
          this->updateRHS(jt, this->publicKeyShares_[jt], vCoeff);
      }


  }

private:
  std::vector<VerificationKey> g__a_i_;

  fetch::consensus::pb::Broadcast
  createCoefficients(const std::vector<PrivateKey> &a_i, const std::vector<PrivateKey> &b_i, uint32_t rank) override {
    fetch::consensus::pb::Broadcast broadcast;
    auto *coefficients = broadcast.mutable_coefficients();
    for (size_t k = 0; k <= this->polynomialDegree_; k++) {
      this->C_ik_[rank][k] = this->computeLHS(g__a_i_[k], this->G, this->H, a_i[k], b_i[k]);
      coefficients->add_coefficients(this->C_ik_[rank][k].toString());
    }
    return broadcast;
  }
};
}
}