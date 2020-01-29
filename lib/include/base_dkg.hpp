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

#include <array>
#include <unordered_map>
#include <cstdint>
#include <cstddef>
#include <iostream>
#include <mutex>

#include "consensus.pb.h"
#include "group_signature_manager.hpp"
#include "messages.hpp"

namespace fetch {
namespace consensus {

/**
 * This class implemnents defines the functions required for the DKG
 */

template<class CryptoType, class CryptoVerificationKey>
class BaseDkg {
public:
  using PrivateKey = typename CryptoType::PrivateKey;
  using Signature = typename CryptoType::Signature;
  using GroupPublicKey = typename CryptoType::GroupPublicKey;
  using VerificationKey = CryptoVerificationKey;
  using MessagePayload = std::string;

  struct DkgOutput {
    GroupPublicKey groupPublicKey;
    std::vector<VerificationKey> publicKeyShares;
    PrivateKey privateKey;

    DkgOutput(GroupPublicKey groupPublicKey1, std::vector<VerificationKey> publicKeyShares1,
              const PrivateKey &privateKey1)
            : groupPublicKey{std::move(groupPublicKey1)}, publicKeyShares{std::move(publicKeyShares1)},
              privateKey{privateKey1} {}
  };

  BaseDkg(uint32_t committeeSize, uint32_t threshold) : committeeSize_{committeeSize}, polynomialDegree_{threshold - 1},
                                                        groupSignatureManager_{threshold} {
    static bool once = []() {
      CryptoType::initCrypto();
      return true;
    }();
    CryptoType::setGenerators(this->G, this->H);
    if (!once) {
      std::cerr << "Node::initPairing failed.\n"; // just to eliminate warnings from the compiler.
    }
    this->publicKeyShares_.resize(this->committeeSize_);
    init(this->C_ik_, this->committeeSize_, this->polynomialDegree_ + 1);
    init(this->A_ik_, this->committeeSize_, this->polynomialDegree_ + 1);
    init(this->s_ij_, this->committeeSize_, this->committeeSize_);
    init(this->sprime_ij_, this->committeeSize_, this->committeeSize_);
    init(this->g__s_ij_, this->committeeSize_, this->committeeSize_);
  }

  virtual ~BaseDkg() = default;
  virtual std::pair<fetch::consensus::pb::Broadcast, std::vector<fetch::consensus::pb::PrivateShares>>
  createCoefficientsAndShares(uint32_t rank) = 0;
  virtual void computeQualCoefficient(fetch::consensus::pb::Broadcast_Coefficients &coefs, uint32_t rank) = 0;
  virtual bool setQualCoefficient(uint32_t from, uint32_t i, const std::string &coef) = 0;
  virtual bool verifyQualCoefficient(uint32_t rank, uint32_t i) const = 0;
  virtual std::pair<bool, bool> verifyQualComplaint(uint32_t nodeIndex, uint32_t fromIndex, const std::string &first,
                                                    const std::string &second) = 0;
  virtual bool runReconstruction(const std::unordered_map<std::string, uint32_t> &nodesMap) = 0;
  virtual void
  computePublicKeys(const std::set<std::string> &qual, const std::unordered_map<std::string, uint32_t> &nodesMap) = 0;
  virtual SignaturesShare getSignatureShare(const MessagePayload &message, uint32_t rank) = 0;
  virtual bool
  addSignatureShare(const fetch::consensus::pb::Gossip_SignatureShare &share_msg, uint32_t miner_index) = 0;

  /**
 * Adds new shares from another DKG member
 *
 * @param from Index of the sender
 * @param rank Our index
 * @param shares The private shares message received from the sender
 * @return bool indicating whether the shares deserialised correctly
 */
  bool setShare(uint32_t from, uint32_t rank, const fetch::consensus::pb::PrivateShares &shares) {
    return s_ij_[from][rank].assign(shares.first()) && sprime_ij_[from][rank].assign(shares.second());
  }

  /**
 * Add new coeffcients
 *
 * @param from Index of the sender
 * @param i Index in vector of coefficients
 * @param coef Value of coefficient vector at index i as string
 * @return bool indicating whether coefficient deserialised correctly
 */
  bool setCoefficient(uint32_t from, uint32_t i, const std::string &coef) {
    if (C_ik_[from][i].isZero()) {
      return C_ik_[from][i].assign(coef);
    }
    return false;
  }

  /**
 * Checks coefficients broadcasted by cabinet member c_i is consistent with the secret shares
 * received from c_i. If false then add to complaints
 *
 * @return Set of muddle addresses of nodes we complain against
 */
  std::set<std::string> computeComplaints(const std::set<std::string> &miners, uint32_t rank) {
    std::set<std::string> complaints_local;
    uint32_t i = 0;
    for (auto &miner : miners) {
      if (i != rank) {
        if (!C_ik_[i][0].isZero() && !s_ij_[i][rank].isZero()) {
          VerificationKey rhs, lhs;
          lhs = computeLHS(g__s_ij_[i][rank], G, H, s_ij_[i][rank], sprime_ij_[i][rank]);
          rhs = computeRHS(rank, C_ik_[i]);
          if (lhs != rhs)
            complaints_local.insert(miner);
        } else {
          complaints_local.insert(miner);
        }
      }
      ++i;
    }
    return complaints_local;
  }

  /**
 * Broadcast private shares after processing complaints
 *
 * @param shares Shares msg to be broadcasted
 * @param reporter String id of the complaint filer
 * @param from Owner of original shares
 * @param to Recipient of original shares
 */
  void broadcastShare(fetch::consensus::pb::Broadcast_Shares &shares, const std::string &reporter,
                      uint32_t from, uint32_t to) const {
    shares.add_first(s_ij_[from][to].toString());
    shares.add_second(sprime_ij_[from][to].toString());
    shares.add_reporter(reporter);
  }

  /**
 * Verify private shares received
 *
 * @param reporterIndex Index of member filing complaint
 * @param fromIndex  Index of the sender of the shares
 * @param rank Our index
 * @param first First share as string
 * @param second Second share as string
 * @return bool for whether the shares pass verification with broadcasted coefficients
 */
  bool verifyShare(uint32_t reporterIndex, uint32_t fromIndex, uint32_t rank, const std::string &first,
                   const std::string &second) {
    PrivateKey s, sprime;
    VerificationKey lhsG, rhsG;

    if (s.assign(first) && sprime.assign(second)) {
      rhsG = computeRHS(reporterIndex, C_ik_[fromIndex]);
      lhsG = computeLHS(G, H, s, sprime);
      if (lhsG == rhsG) {
        if (reporterIndex == rank) {
          s_ij_[fromIndex][rank] = s;
          sprime_ij_[fromIndex][rank] = sprime;
          g__s_ij_[fromIndex][rank].setZero();
          g__s_ij_[fromIndex][rank].mult(G, s_ij_[fromIndex][rank]);
        }
        return true;
      }
      return false;
    }
    return false;
  }

  /**
 * Compute own private key
 *
 * @param rank Our index
 * @param quals Indices of qualified members
 */
  void computePrivateKey(uint32_t rank, const std::vector<uint32_t> &quals) {
    std::lock_guard<std::mutex> lock(mutex_);
    privateKey_.setZero();
    xprime_i_.setZero();
    for (auto &iq_index : quals) {
      privateKey_.add(privateKey_, s_ij_[iq_index][rank]);
      xprime_i_.add(xprime_i_, sprime_ij_[iq_index][rank]);
    }
  }

  /**
 * Inserting reconstruction shares
 *
 * @param id String id of member being reconstructed
 * @param index Index of member being reconstructed
 * @param rank Our index
 */
  void newReconstructionShare(const std::string &id, uint32_t index, uint32_t rank) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (reconstructionShares_.find(id) == reconstructionShares_.end()) {
      reconstructionShares_.insert({id, {{}, std::vector<PrivateKey>(committeeSize_)}});
    }
    reconstructionShares_.at(id).first.insert(rank);
    reconstructionShares_.at(id).second[rank] = s_ij_[index][rank];
  }

  /**
   * Verify reconstruction shares received
   *
   * @param nodeIndex Index of node who is being reconstructed
   * @param fromIndex Index of the sender of the shares
   * @param reporter Index of the person filing complaint
   * @param first First secret share as string
   * @param second Second secret share as string
   */
  void verifyReconstructionShare(uint32_t nodeIndex, uint32_t fromIndex, const std::string &reporter,
                                 const std::string &first,
                                 const std::string &second) {
    std::lock_guard<std::mutex> lock(mutex_);
    VerificationKey lhs, rhs;
    PrivateKey s, sprime;

    if (s.assign(first) and sprime.assign(second)) {
      lhs = computeLHS(G, H, s, sprime);
      rhs = computeRHS(fromIndex, C_ik_[nodeIndex]);
      bool check = lhs == rhs;
      if (check) {
        if (reconstructionShares_.find(reporter) == reconstructionShares_.end()) {
          reconstructionShares_.insert(
                  {reporter, {{}, std::vector<PrivateKey>(committeeSize_)}});
        } else if (reconstructionShares_.at(reporter).second[fromIndex].isZero()) {
          return;
        }
        reconstructionShares_.at(reporter).first.insert(fromIndex); // good share received
        reconstructionShares_.at(reporter).second[fromIndex] = s;
      }
    }
  }

  std::string computeGroupSignature(const MessagePayload &message) {
    std::lock_guard<std::mutex> lock(mutex_);
    assert(groupSignatureManager_.numSignatureShares(message) > polynomialDegree_);
    Signature sig{lagrangeInterpolation(groupSignatureManager_.signatureShares(message))};
    groupSignatureManager_.addSignedMessage(message, sig);
    return sig.toString();
  }

  void setDkgOutput(const DkgOutput &output) {
    std::lock_guard<std::mutex> lock(mutex_);
    groupPublicKey_ = output.groupPublicKey;
    privateKey_ = output.privateKey;

    for (size_t i = 0; i < publicKeyShares_.size(); i++) {
      publicKeyShares_[i] = output.publicKeyShares[i];
    }
  }

  /// Getter functions
  /// @{
  std::string groupPublicKey() const {
    if (groupPublicKey_.isZero()) {
      return "";
    }
    return groupPublicKey_.toString();
  }

  std::vector<std::string> publicKeyShares() const {
    std::vector<std::string> public_key_shares;
    for (uint32_t i = 0; i < committeeSize_; ++i) {
      assert(!publicKeyShares_[i].isZero());
      public_key_shares.push_back(publicKeyShares_[i].toString());
      assert(!public_key_shares[i].empty());
    }
    return public_key_shares;
  }
  /// @}

  /// Threshold Signing Methods
  /// @{
  std::string groupSignature(const MessagePayload &message) const {
    return groupSignatureManager_.groupSignature(message);
  }

  bool groupSignatureCompleted(const MessagePayload &message) const {
    return groupSignatureManager_.signatureCompleted(message);
  }

  size_t numSignatureShares(const MessagePayload &message) const {
    return groupSignatureManager_.numSignatureShares(message);
  }

  bool isFinished(const MessagePayload &message) const {
    return groupSignatureManager_.numSignatureShares(message) > polynomialDegree_;
  }
  /// @}

  static void initCrypto() {
    CryptoType::initCrypto();
  }

  template<class Generator>
  static void setGenerator(Generator &generator) {
    CryptoType::setGenerator(generator);
  }

  template<class Generator>
  static void setGenerators(Generator &generator1, Generator &generator2) {
    CryptoType::setGenerators(generator1, generator2);
  }

  /**
 * Computes signature share of a message
 *
 * @param message Message to be signed
 * @param privateKey Secret key share
 * @return Signature share
 */
  static Signature sign(const MessagePayload &message, const PrivateKey &privateKey) {
    Signature PH;
    Signature sign;
    PH.hashAndMap(message);
    sign.mult(PH, privateKey);
    return sign;
  }

  /**
   * Computes the group signature using the indices and signature shares of threshold_ + 1
   * parties
   *
   * @param shares Unordered map of indices and their corresponding signature shares
   * @return Group signature
   */
  static Signature lagrangeInterpolation(const std::unordered_map<uint32_t, typename CryptoType::Signature> &shares) {
    assert(!shares.empty());
    if (shares.size() == 1) {
      return shares.begin()->second;
    }
    Signature res;

    PrivateKey a{1};
    for (auto &p : shares) {
      a.mult(a, typename CryptoType::PrivateKey{uint32_t(p.first + 1)});
    }

    for (auto &p1 : shares) {
      typename CryptoType::PrivateKey b{uint32_t(p1.first + 1)};
      for (auto &p2 : shares) {
        if (p2.first != p1.first) {
          typename CryptoType::PrivateKey local_share1{uint32_t(p1.first)}, local_share2{uint32_t(p2.first)};
          local_share2.sub(local_share2, local_share1);
          b.mult(b, local_share2);
        }
      }
      b.inv(b);
      b.mult(a, b);

      typename CryptoType::Signature t;
      t.mult(p1.second, b);
      res.add(res, t);
    }
    return res;
  }

  /**
   * Generates the group public key, public key shares and private key share for a number of
   * parties and a given signature threshold. Nodes must be allocated the outputs according
   * to their index in the cabinet.
   *
   * @param committeeSize Number of parties for which private key shares are generated
   * @param threshold Number of parties required to generate a group signature
   * @return Vector of DkgOutputs containing the data to be given to each party
   */
  static std::vector<DkgOutput> trustedDealer(uint32_t committeeSize, uint32_t threshold) {
    std::vector<DkgOutput> output;
    VerificationKey generator;
    GroupPublicKey generator2;
    setGenerator(generator);
    setGenerator(generator2);

    // Construct polynomial of degree threshold - 1
    std::vector<PrivateKey> vec_a;
    vec_a.resize(threshold);
    for (uint32_t ii = 0; ii < threshold; ++ii) {
      vec_a[ii].random();
    }

    std::vector<VerificationKey> publicKeyShares(committeeSize);
    std::vector<PrivateKey> privateKeyShares(committeeSize);

    // Group secret key is polynomial evaluated at 0
    GroupPublicKey groupPublicKey;
    PrivateKey group_private_key = vec_a[0];
    groupPublicKey.mult(generator2, group_private_key);

    // Generate committee public keys from their private key contributions
    for (uint32_t i = 0; i < committeeSize; ++i) {
      PrivateKey pow{i + 1}, tmpF, privateKey, cryptoRank{i + 1};
      // Private key is polynomial evaluated at index i
      privateKey = vec_a[0];
      for (uint32_t k = 1; k < vec_a.size(); k++) {
         tmpF.mult(pow, vec_a[k]);
         privateKey.add(privateKey, tmpF);
         pow.mult(pow, cryptoRank);        // adjust index in computation
      }
      // Public key from private
      VerificationKey publicKey;
      publicKey.mult(generator, privateKey);
      publicKeyShares[i] = publicKey;
      privateKeyShares[i] = privateKey;
    }

    assert(publicKeyShares.size() == committeeSize);
    assert(privateKeyShares.size() == committeeSize);
    // Compute outputs for each member
    for (uint32_t i = 0; i < committeeSize; ++i) {
      output.emplace_back(groupPublicKey, publicKeyShares, privateKeyShares[i]);
    }
    return output;
  }

protected:
  const uint32_t committeeSize_; ///< Number of participants in DKG
  uint32_t polynomialDegree_; ///< Degree of polynomial in DKG
  GroupSignatureManager<BaseDkg> groupSignatureManager_;

  VerificationKey G;
  VerificationKey H;

  /// Output of the DKG
  /// @{
  PrivateKey privateKey_;
  GroupPublicKey groupPublicKey_;
  std::vector<VerificationKey> publicKeyShares_;
  /// @}

  /// Temporary variables in DKG
  /// @{
  PrivateKey xprime_i_;
  std::vector<std::vector<PrivateKey> > s_ij_, sprime_ij_;
  std::vector<std::vector<VerificationKey>> C_ik_;
  std::vector<std::vector<VerificationKey>> A_ik_;
  std::vector<std::vector<VerificationKey>> g__s_ij_;
  /// @}

  std::unordered_map<std::string, std::pair<std::set<std::size_t>, std::vector<PrivateKey>>> reconstructionShares_;
  ///< Map from id of node_i in complaints to a pair <parties which
  ///< exposed shares of node_i, the shares that were exposed>
  std::mutex mutex_;

  virtual fetch::consensus::pb::Broadcast
  createCoefficients(const std::vector<PrivateKey> &a_i, const std::vector<PrivateKey> &b_i, uint32_t rank) = 0;

  template<typename T>
  static void init(std::vector<std::vector<T>> &data, uint32_t i, uint32_t j) {
    data.resize(i);
    for (auto &data_i : data) {
      data_i.resize(j);
    }
  }

  std::vector<fetch::consensus::pb::PrivateShares>
  createShares(const std::vector<PrivateKey> &a_i, const std::vector<PrivateKey> &b_i, uint32_t rank) {
    std::vector<fetch::consensus::pb::PrivateShares> res;
    for (size_t j = 0; j < committeeSize_; ++j) {
      computeShares(s_ij_[rank][j], sprime_ij_[rank][j], a_i, b_i, j);
      if (j != rank) {
        PrivateShares shares{s_ij_[rank][j].toString(), sprime_ij_[rank][j].toString()};
        res.emplace_back(shares.handle());
      }
    }
    return res;
  }

  /**
   * LHS and RHS functions are used for checking consistency between publicly broadcasted coefficients
   * and secret shares distributed privately
   */
  static VerificationKey
  computeLHS(VerificationKey &tmpG, const VerificationKey &G,
             const VerificationKey &H, const PrivateKey &share1,
             const PrivateKey &share2) {
    {
      VerificationKey tmp2G, lhsG;
      tmpG.mult(G, share1);
      tmp2G.mult(H, share2);
      lhsG.add(tmpG, tmp2G);

      return lhsG;
    }
  }

  static VerificationKey
  computeLHS(const VerificationKey &G, const VerificationKey &H,
             const PrivateKey &share1, const PrivateKey &share2) {
    VerificationKey tmpG;
    return computeLHS(tmpG, G, H, share1, share2);
  }

  static void updateRHS(size_t rank, VerificationKey &rhsG,
                        const std::vector<VerificationKey> &input) {
    PrivateKey tmpF{uint32_t(rank + 1)}, cryptoRank{uint32_t(rank + 1)};
    VerificationKey tmpG;
    assert(input.size() > 0);
    for (size_t k = 1; k < input.size(); k++) {
      tmpG.mult(input[k], tmpF);
      rhsG.add(rhsG, tmpG);
      tmpF.mult(tmpF, cryptoRank); // adjust index $i$ in computation
    }
  }

  static VerificationKey
  computeRHS(size_t rank, const std::vector<VerificationKey> &input) {
    VerificationKey rhsG{input[0]};
    assert(input.size() > 0);
    updateRHS(rank, rhsG, input);
    return rhsG;
  }

  /**
  * Given two polynomials (f and f') with coefficients a_i and b_i, we compute the evaluation of
  * these polynomials at different points
  *
  * @param s_i The value of f(rank)
  * @param sprime_i The value of f'(rank)
  * @param a_i The vector of coefficients for f
  * @param b_i The vector of coefficients for f'
  * @param rank The point at which you evaluate the polynomial
  */
  static void
  computeShares(PrivateKey &s_i, PrivateKey &sprime_i,
                const std::vector<PrivateKey> &a_i,
                const std::vector<PrivateKey> &b_i,
                size_t rank) {
    PrivateKey pow{uint32_t(rank + 1)}, tmpF, cryptoRank{uint32_t(rank + 1)};
    assert(a_i.size() == b_i.size());
    assert(a_i.size() > 0);
    s_i = a_i[0];
    sprime_i = b_i[0];
    for (size_t k = 1; k < a_i.size(); k++) {
      tmpF.mult(pow, b_i[k]);
      sprime_i.add(sprime_i, tmpF);
      tmpF.mult(pow, a_i[k]);
      s_i.add(s_i, tmpF);
      pow.mult(pow, cryptoRank); // adjust index $j$ in computation
    }
  }

  /**
   * Computes the coefficients of a polynomial
   *
   * @param a Points at which polynomial has been evaluated
   * @param b Value of the polynomial at points a
   * @return The vector of coefficients of the polynomial
   */
  static std::vector<PrivateKey>
  interpolatePolynom(const std::vector<PrivateKey> &a,
                     const std::vector<PrivateKey> &b) {
    size_t m = a.size();
    if ((b.size() != m) || (m == 0))
      throw std::invalid_argument("mcl_interpolate_polynom: bad m");
    std::vector<PrivateKey> prod{a}, res(m);
    for (size_t k = 0; k < m; k++) {
      PrivateKey t1{1};
      for (long i = k - 1; i >= 0; i--) {
        t1.mult(t1, a[k]);
        t1.add(t1, prod[i]);
      }

      PrivateKey t2;
      for (long i = k - 1; i >= 0; i--) {
        t2.mult(t2, a[k]);
        t2.add(t2, res[i]);
      }

      t2.sub(b[k], t2);
      t1.div(t2, t1);

      for (size_t i = 0; i < k; i++) {
        t2.mult(prod[i], t1);
        res[i].add(res[i], t2);
      }
      res[k] = t1;
      if (k < (m - 1)) {
        if (k == 0)
          prod[0].negate(prod[0]);
        else {
          t1.negate(a[k]);
          prod[k].add(t1, prod[k - 1]);
          for (long i = k - 1; i >= 1; i--) {
            t2.mult(prod[i], t1);
            prod[i].add(t2, prod[i - 1]);
          }
          prod[0].mult(prod[0], t1);
        }
      }
    }
    return res;
  }
};
}
}