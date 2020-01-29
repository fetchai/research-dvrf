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

#include "crypto_mcl.hpp"

namespace fetch {
namespace consensus {

CryptoMcl::PrivateKey::PrivateKey() {
  clear();
}

CryptoMcl::PrivateKey::PrivateKey(uint32_t num) {
  clear();
  bn::Fr::add(*this, *this, num);
}

void CryptoMcl::PrivateKey::random() {
  setRand();
}

void CryptoMcl::PrivateKey::increment() {
  bn::Fr::add(*this, *this, 1);
}

std::string CryptoMcl::PrivateKey::toString() const {
  return getStr();
}

bool CryptoMcl::PrivateKey::assign(const std::string &s) {
  bool set{false};
  setStr(&set, s.data());
  return set;
}

void CryptoMcl::PrivateKey::setZero() {
  clear();
}

void CryptoMcl::PrivateKey::add(const PrivateKey &left, const PrivateKey &right) {
  bn::Fr::add(*this, left, right);
}

void CryptoMcl::PrivateKey::sub(const PrivateKey &left, const PrivateKey &right) {
  bn::Fr::sub(*this, left, right);
}

void CryptoMcl::PrivateKey::mult(const PrivateKey &left, const PrivateKey &right) {
  bn::Fr::mul(*this, left, right);
}

void CryptoMcl::PrivateKey::inv(const PrivateKey &inv) {
  bn::Fr::inv(*this, inv);
}

void CryptoMcl::PrivateKey::negate(const PrivateKey &neg) {
  bn::Fr::neg(*this, neg);
}

void CryptoMcl::PrivateKey::pow(const PrivateKey &left, uint32_t pow) {
  bn::Fr::pow(*this, left, pow);
}

void CryptoMcl::PrivateKey::div(const PrivateKey &left, const PrivateKey &right) {
  bn::Fr::div(*this, left, right);
}

void CryptoMcl::PrivateKey::setHashOf(const Signature &generator, const Signature &Hm, const Signature &publicKey,
                                      const Signature &sig, const Signature &com1, const Signature &com2) {
  std::ostringstream os;
  os << generator << Hm << publicKey << sig << com1 << com2;
  bn::Fr::setHashOf(os.str());
}

CryptoMcl::Signature::Signature() {
  clear();
}

void CryptoMcl::Signature::setZero() {
  clear();
}

bool CryptoMcl::Signature::assign(const std::string &s) {
  bool set{false};
  setStr(&set, s.data());
  return set;
}

void CryptoMcl::Signature::mult(const Signature &left, const PrivateKey &right) {
  bn::G1::mul(*this, left, right);
}

void CryptoMcl::Signature::add(const Signature &left, const Signature &right) {
  bn::G1::add(*this, left, right);
}

void CryptoMcl::Signature::hashAndMap(const std::string &payload) {
  bn::Fp Hm;
  Hm.setHashOf(payload);
  bn::mapToG1(*this, Hm);
}

std::string CryptoMcl::Signature::toString() const {
  return getStr();
}

CryptoMcl::GroupPublicKey::GroupPublicKey() {
  clear();
}

void CryptoMcl::GroupPublicKey::setZero() {
  clear();
}

bool CryptoMcl::GroupPublicKey::assign(const std::string &s) {
  bool set{false};
  setStr(&set, s.data());
  return set;
}

void CryptoMcl::GroupPublicKey::mult(const GroupPublicKey &left, const PrivateKey &right) {
  bn::G2::mul(*this, left, right);
}

void CryptoMcl::GroupPublicKey::add(const GroupPublicKey &left, const GroupPublicKey &right) {
  bn::G2::add(*this, left, right);
}

void CryptoMcl::GroupPublicKey::hashAndMap(const std::string &payload) {
  bn::hashAndMapToG2(*this, payload.data(), payload.size());
}

std::string CryptoMcl::GroupPublicKey::toString() const {
  return getStr();
}

CryptoMcl::Pairing::Pairing() {
  clear();
}

void CryptoMcl::Pairing::map(const Signature &g1, const GroupPublicKey &g2) {
  bn::pairing(*this, g1, g2);
}

bool CryptoMcl::Proof::assign(const std::pair<std::string, std::string> &s) {
  return first.assign(s.first) && second.assign(s.second);
}

std::pair<std::string, std::string> CryptoMcl::Proof::toString() const {
  return std::make_pair(first.toString(), second.toString());
}

void CryptoMcl::initCrypto() {
#ifdef BLS12
  mcl::fp::Mode g_mode;
bn::initPairing(mcl::BLS12_381, g_mode);
#endif
#ifdef BN384
  mcl::fp::Mode g_mode;
bn::initPairing(mcl::BN381_1, g_mode);
#endif
#ifdef BN512
  mcl::fp::Mode g_mode;
bn::initPairing(mcl::BN462, g_mode);
#endif
#if !defined(BLS12) && !defined(BN384) && !defined(BN512)
  bn::initPairing();
#endif
}

}
}