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

#include <assert.h>
#include <cstddef>
#include <cstring>

#include "crypto_sodium.hpp"

namespace fetch {
namespace consensus {

CryptoSodium::PrivateKey::PrivateKey() {
  sodium_memzero(data(), size());
}

CryptoSodium::PrivateKey::PrivateKey(uint32_t num) {
  sodium_memzero(data(), size());
  sodium_add(data(), (unsigned char *) &num, sizeof(uint32_t));
}

void CryptoSodium::PrivateKey::random() {
  crypto_core_ristretto255_scalar_random(data());
}

void CryptoSodium::PrivateKey::increment() {
  sodium_increment(data(), crypto_core_ristretto255_SCALARBYTES);
}

std::string CryptoSodium::PrivateKey::toString() const {
  char hex[size() * 2 + 1];
  std::string out;
  bool check = sodium_bin2hex(hex, size() * 2 + 1, data(), size());
  assert(check);
  out.assign(hex, size() * 2);
  return out;
}

bool CryptoSodium::PrivateKey::assign(const std::string &s) {
  if (s.size() != 2 * size()) {
    return false;
  }
  int check = sodium_hex2bin(data(), size(), s.c_str(), s.size(), nullptr, nullptr, nullptr);
  return (check == 0);
}

void CryptoSodium::PrivateKey::setZero() {
  sodium_memzero(data(), size());
}

void CryptoSodium::PrivateKey::add(const PrivateKey &left, const PrivateKey &right) {
  crypto_core_ristretto255_scalar_add(data(), left.data(), right.data());
}

void CryptoSodium::PrivateKey::sub(const PrivateKey &left, const PrivateKey &right) {
  crypto_core_ristretto255_scalar_sub(data(), left.data(), right.data());
}

bool CryptoSodium::PrivateKey::isZero() const {
  return sodium_is_zero(data(), size());
}

void CryptoSodium::PrivateKey::mult(const PrivateKey &left, const PrivateKey &right) {
  crypto_core_ristretto255_scalar_mul(data(), right.data(), left.data());
}

void CryptoSodium::PrivateKey::inv(const PrivateKey &inv) {
  int check = crypto_core_ristretto255_scalar_invert(data(), inv.data());
  assert(check == 0);
}

void CryptoSodium::PrivateKey::negate(const PrivateKey &neg) {
  crypto_core_ristretto255_scalar_negate(data(), neg.data());
}

void CryptoSodium::PrivateKey::pow(const PrivateKey &in, int32_t pow) {
  if (pow == 0)
    sodium_hex2bin(data(), size(),
                   "0100000000000000000000000000000000000000000000000000000000000000",
                   sizeof "01000000000000000000000000000000000000000000000000000000000000000" - (size_t) 1U, nullptr,
                   nullptr, nullptr);

  if (pow == 1)
    memcpy(data(), in.data(), size());

  if (pow > 1) {
    PrivateKey localin, localout;
    memcpy(localin.data(), in.data(), size());

    localout.mult(localin, localin); //^2
    for (int32_t i = 2; i < pow; i++)
      localout.mult(localout, localin);

    memcpy(data(), localout.data(), size());
  }
}

void CryptoSodium::PrivateKey::div(const PrivateKey &num, const PrivateKey &denom) {
  PrivateKey local_denom;
  local_denom.inv(denom);
  mult(num, local_denom);
}

void CryptoSodium::PrivateKey::setHashOf(const Signature &generator, const Signature &Hm, const Signature &publicKey,
                                         const Signature &sig, const Signature &com1, const Signature &com2) {
  assert(size() >= crypto_generichash_BYTES);
  unsigned char chm[generator.size() + Hm.size() + publicKey.size() + sig.size() + com1.size() + com2.size()];
  sodium_memzero(chm, sizeof chm);

  //compute the hash
  memcpy(chm, generator.data(), generator.size());
  memcpy(chm + generator.size(), Hm.data(), Hm.size());
  memcpy(chm + generator.size() + Hm.size(), publicKey.data(), publicKey.size());
  memcpy(chm + generator.size() + Hm.size() + publicKey.size(), sig.data(), sig.size());
  memcpy(chm + generator.size() + Hm.size() + publicKey.size() + sig.size(), com1.data(), com1.size());
  memcpy(chm + generator.size() + Hm.size() + publicKey.size() + sig.size() + com1.size(), com2.data(), com2.size());

  crypto_generichash(data(), size(), chm, sizeof chm, NULL, 0);
}

CryptoSodium::Signature::Signature() {
  sodium_memzero(data(), size());
}

CryptoSodium::Signature::Signature(uint32_t num) {
  sodium_memzero(data(), size());
  sodium_add(data(), (unsigned char *) &num, sizeof(uint32_t));
}

bool CryptoSodium::Signature::assign(const std::string &s) {
  assert(s.size() == 2 * size());
  int check = sodium_hex2bin(data(), size(), s.c_str(), s.size(), nullptr, nullptr, nullptr);
  return (check == 0);
}

void CryptoSodium::Signature::mult(const Signature &left, const PrivateKey &right) {
  int check = crypto_scalarmult_ristretto255(data(), right.data(), left.data());
  assert(check == 0);
}

void CryptoSodium::Signature::add(const Signature &left, const Signature &right) {
  int check = crypto_core_ristretto255_add(data(), left.data(), right.data());
  assert(check == 0);
}

void CryptoSodium::Signature::sub(const Signature &left, const Signature &right) {
  int check = crypto_core_ristretto255_sub(data(), left.data(), right.data());
  assert(check == 0);
}

void CryptoSodium::Signature::setZero() {
  sodium_memzero(data(), size());
}

void CryptoSodium::Signature::hashAndMap(const std::string &payload) {
  // Put message into unsigned char
  unsigned char m[payload.size()];
  sodium_memzero(m, sizeof m);
  memcpy(m, payload.c_str(), payload.size());

  // Hash and map to point on curve
  unsigned char hash[64];
  sodium_memzero(hash, sizeof hash);
  crypto_generichash(hash, sizeof hash, m, sizeof m, NULL, 0);
  crypto_core_ristretto255_from_hash(data(), hash);
}

std::string CryptoSodium::Signature::toString() const {
  char hex[size() * 2 + 1];
  std::string out;
  bool check = sodium_bin2hex(hex, size() * 2 + 1, data(), size());
  assert(check);
  out.assign(hex, size() * 2);
  return out;
}

bool CryptoSodium::Signature::isZero() const {
  return sodium_is_zero(data(), size());
}

std::pair<std::string, std::string> CryptoSodium::Proof::toString() const {
  return std::make_pair(first.toString(), second.toString());
}

bool CryptoSodium::Proof::assign(const std::pair<std::string, std::string> &s) {
  return first.assign(s.first) && second.assign(s.second);
}

void CryptoSodium::initCrypto() {
  int check = sodium_init();
  assert(check != -1);
}

void CryptoSodium::setGenerator(Signature &group_g) {
  group_g.assign("38bc887d3d4cc530c37e58df4ab9ad879ba8f70c05df38193edb5490150b7425");
}

void CryptoSodium::setGenerators(Signature &group_g, Signature &group_h) {
  group_g.assign("38bc887d3d4cc530c37e58df4ab9ad879ba8f70c05df38193edb5490150b7425");
  group_h.assign("a862c62015c694056b0d2db59d6238827fa6b7d780065ebcc7bd97a919b1e968");
}
}
}