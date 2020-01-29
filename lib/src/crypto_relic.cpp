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

#include "crypto_relic.hpp"
//
// used for import/export from/to hex string as
// libsodium is part of build anyway.
// probably should be changed with a better
// serialisation to remove dependency.
//
#include "sodium/utils.h"

namespace fetch {
namespace consensus {

CryptoRelic::PrivateKey::PrivateKey() {
  bn_null(n);
  bn_new(n);
  g1_get_ord(n);

  bn_null(bn);
  bn_new(bn);
  bn_zero(bn);
}

CryptoRelic::PrivateKey::PrivateKey(uint32_t num) {
  bn_null(n);
  bn_new(n);
  g1_get_ord(n);

  bn_null(bn);
  bn_new(bn);
  bn_zero(bn);
  bn_add_dig(bn, bn, (dig_t) num);
}

void CryptoRelic::PrivateKey::operator=(const PrivateKey &right) {
  bn_copy(bn, right.data());
}

bool CryptoRelic::PrivateKey::operator==(const PrivateKey &right) const {
  return (bn_cmp(bn, right.data()) == RLC_EQ);
}

bool CryptoRelic::PrivateKey::operator!=(const PrivateKey &right) const {
  return (bn_cmp(bn, right.data()) != RLC_EQ);
}

void CryptoRelic::PrivateKey::setZero() {
  bn_zero(bn);
}

bool CryptoRelic::PrivateKey::isZero() const {
  return (bn_is_zero(bn));
}

const bn_st *CryptoRelic::PrivateKey::data() const {
  return bn;
}

void CryptoRelic::PrivateKey::random() {
  bn_rand_mod(bn, n);
}

void CryptoRelic::PrivateKey::increment() {
  bn_add_dig(bn, bn, 1);
  bn_mod(bn, bn, n);
}

std::string CryptoRelic::PrivateKey::toString() const {
  size_t len = RLC_CEIL(RLC_BN_BITS, 8);
  uint8_t bin[len];
  bn_write_bin(bin, len, bn);

  //to string
  char hex[len * 2 + 1];
  std::string out;
  bool check = sodium_bin2hex(hex, len * 2 + 1, bin, len);
  assert(check);
  out.assign(hex, len * 2);
  return out;
}

bool CryptoRelic::PrivateKey::assign(const std::string &s) {
  size_t len = RLC_CEIL(RLC_BN_BITS, 8);
  if (s.size() != 2 * len) {
    return false;
  }
  bn_zero(bn);
  uint8_t bin[s.size() / 2];
  sodium_hex2bin(bin, len, s.c_str(), s.size(), nullptr, nullptr, nullptr);
  bn_read_bin(bn, bin, s.size() / 2);

  return true;
}

void CryptoRelic::PrivateKey::add(const PrivateKey &left, const PrivateKey &right) {
  bn_add(bn, left.data(), right.data());
  bn_mod(bn, bn, n);
}

void CryptoRelic::PrivateKey::sub(const PrivateKey &left, const PrivateKey &right) {
  bn_sub(bn, left.data(), right.data());
  bn_mod(bn, bn, n);
}

void CryptoRelic::PrivateKey::mult(const PrivateKey &left, const PrivateKey &right) {
  bn_mul(bn, left.data(), right.data());
  bn_mod(bn, bn, n);
}

void CryptoRelic::PrivateKey::div(const PrivateKey &left, const PrivateKey &right) {
  bn_div(bn, left.data(), right.data());
  bn_mod(bn, bn, n);
}

void CryptoRelic::PrivateKey::pow(const PrivateKey &left, uint32_t pow) {
  PrivateKey cryptoPow{pow};
  bn_mxp(bn, left.data(), cryptoPow.data(), n);
}

void CryptoRelic::PrivateKey::inv(const PrivateKey &inv) {
  //Fermat
  /*
  bn_t m;
  bn_null(m);
  bn_new(m);
  bn_sub_dig(m, n, (dig_t)2);
  bn_mxp(bn, inv.data(), m, n);
  */

  //Euclid
  bn_t gcd;
  bn_null(gcd);
  bn_new(gcd);

  bn_t x, y;
  bn_null(x);
  bn_null(y);
  bn_new(x);
  bn_new(y);
  bn_gcd_ext(gcd, x, y, inv.data(), n);
  bn_copy(bn, x);
  /**/
}

void CryptoRelic::PrivateKey::negate(const PrivateKey &neg) {
  bn_neg(bn, neg.data());
  bn_mod(bn, bn, n);
}

void CryptoRelic::PrivateKey::setHashOf(const Signature &generator, const Signature &Hm, const Signature &publicKey,
                                        const Signature &sig, const Signature &com1, const Signature &com2) {

  size_t generator_len = g1_size_bin(generator.data(), 1);
  size_t Hm_len = g1_size_bin(Hm.data(), 1);
  size_t publicKey_len = g1_size_bin(publicKey.data(), 1);
  size_t sig_len = g1_size_bin(sig.data(), 1);
  size_t com1_len = g1_size_bin(com1.data(), 1);
  size_t com2_len = g1_size_bin(com2.data(), 1);
  size_t bin_len = generator_len + Hm_len + publicKey_len + sig_len + com1_len + com2_len;

  uint8_t bin[bin_len];

  g1_write_bin(bin, generator_len, generator.data(), 1);
  g1_write_bin(bin + generator_len, Hm_len, Hm.data(), 1);
  g1_write_bin(bin + generator_len + Hm_len, publicKey_len, publicKey.data(), 1);
  g1_write_bin(bin + generator_len + Hm_len + publicKey_len, sig_len, sig.data(), 1);
  g1_write_bin(bin + generator_len + Hm_len + publicKey_len + sig_len, com1_len, com1.data(), 1);
  g1_write_bin(bin + generator_len + Hm_len + publicKey_len + sig_len + com1_len, com2_len, com2.data(), 1);

  uint8_t digest[64];
  md_map_sh512(digest, (const uint8_t *) bin, bin_len);
  bn_read_bin(bn, digest, 64);
}

CryptoRelic::Signature::Signature() {
  g1_null(g1);
  g1_new(g1);
  g1_set_infty(g1);
}

CryptoRelic::Signature::Signature(bool isGenerator) {
  if (isGenerator) {
    g1_null(g1);
    g1_new(g1);
    g1_get_gen(g1);
  } else {
    Signature();
  }
}

void CryptoRelic::Signature::operator=(const Signature &right) {
  g1_copy(g1, right.data());
}

bool CryptoRelic::Signature::operator==(const Signature &right) const {
  return (g1_cmp(g1, right.data()) == RLC_EQ);
}

bool CryptoRelic::Signature::operator!=(const Signature &right) const {
  return (g1_cmp(g1, right.data()) != RLC_EQ);
}

void CryptoRelic::Signature::fromCStr(const uint8_t *num, int size) {
  g1_map(g1, num, size);
}

const ep_st *CryptoRelic::Signature::data() const {
  return g1;
}

bool CryptoRelic::Signature::assign(const std::string &s) {
  g1_set_infty(g1);
  uint8_t bin[s.size() / 2];
  sodium_hex2bin(bin, s.size() / 2, s.c_str(), s.size(), nullptr, nullptr, nullptr);
  g1_read_bin(g1, bin, s.size() / 2);

  return true;
}

void CryptoRelic::Signature::mult(const Signature &left, const PrivateKey &right) {
  g1_mul(g1, left.data(), right.data());
}

void CryptoRelic::Signature::add(const Signature &left, const Signature &right) {
  g1_add(g1, left.data(), right.data());
}

void CryptoRelic::Signature::hashAndMap(const std::string &payload) {
  uint8_t digest[64];
  md_map_sh512(digest, (const uint8_t *) payload.c_str(), payload.size());
  fromCStr(digest, 64);
}

std::string CryptoRelic::Signature::toString() const {
  size_t len = g1_size_bin(g1, 1);
  uint8_t bin[len + 1];
  g1_write_bin(bin, len, g1, 1);

  //to string
  char hex[len * 2 + 1];
  std::string out;
  bool check = sodium_bin2hex(hex, len * 2 + 1, bin, len);
  assert(check);
  out.assign(hex, len * 2);
  return out;
}

bool CryptoRelic::Signature::isZero() const {
  return (g1_is_infty(g1));
}

void CryptoRelic::Signature::setZero() {
  g1_set_infty(g1);
}

CryptoRelic::GroupPublicKey::GroupPublicKey() {
  g2_null(g2);
  g2_new(g2);
  g2_set_infty(g2);
}

CryptoRelic::GroupPublicKey::GroupPublicKey(bool isGenerator) {
  if (isGenerator) {
    g2_null(g2);
    g2_new(g2);
    g2_get_gen(g2);
  } else {
    GroupPublicKey();
  }
}

void CryptoRelic::GroupPublicKey::operator=(const GroupPublicKey &right) {
  g2_copy(g2, const_cast<ep2_st *>(right.data()));
}

bool CryptoRelic::GroupPublicKey::operator==(const GroupPublicKey &right) const {
  return (g2_cmp(const_cast<ep2_st *>(g2), const_cast<ep2_st *>(right.data())) == RLC_EQ);
}

bool CryptoRelic::GroupPublicKey::operator!=(const GroupPublicKey &right) const {
  return (g2_cmp(const_cast<ep2_st *>(g2), const_cast<ep2_st *>(right.data())) != RLC_EQ);
}

void CryptoRelic::GroupPublicKey::setZero() {
  g2_set_infty(g2);
}

const ep2_st *CryptoRelic::GroupPublicKey::data() const {
  return g2;
}

bool CryptoRelic::GroupPublicKey::assign(const std::string &s) {
  //size_t len = g2_size_bin(const_cast<ep2_st*>(g2), 1);
  //if (s.size() != 2 * len) {
  //	return false;
  //}
  g2_set_infty(g2);
  uint8_t bin[s.size() / 2];
  sodium_hex2bin(bin, s.size() / 2, s.c_str(), s.size(), nullptr, nullptr, nullptr);
  g2_read_bin(const_cast<ep2_st *>(g2), bin, s.size() / 2);

  return true;
}

void CryptoRelic::GroupPublicKey::mult(const GroupPublicKey &left, const PrivateKey &right) {
  g2_mul(g2, const_cast<ep2_st *>(left.data()), const_cast<bn_st *>(right.data()));
}

void CryptoRelic::GroupPublicKey::add(const GroupPublicKey &left, const GroupPublicKey &right) {
  g2_add(g2, const_cast<ep2_st *>(left.data()), const_cast<ep2_st *>(right.data()));
}

std::string CryptoRelic::GroupPublicKey::toString() const {
  size_t len = g2_size_bin(const_cast<ep2_st *>(g2), 1);
  uint8_t bin[2 * len + 1];
  g2_write_bin(bin, len, const_cast<ep2_st *>(g2), 1);

  //to string
  char hex[len * 2 + 1];
  std::string out;
  bool check = sodium_bin2hex(hex, len * 2 + 1, bin, len);
  assert(check);
  out.assign(hex, len * 2);
  return out;
}

bool CryptoRelic::GroupPublicKey::isZero() const {
  return (g2_is_infty(const_cast<ep2_st *>(g2)));
}

CryptoRelic::Pairing::Pairing() {
  gt_null(e);gt_new(e);
}

bool CryptoRelic::Pairing::operator==(const Pairing &e2) {
  return (gt_cmp(e, const_cast<fp6_t *>(e2.data())) == RLC_EQ);
}

bool CryptoRelic::Pairing::operator!=(const Pairing &e2) {
  return (gt_cmp(e, const_cast<fp6_t *>(e2.data())) != RLC_EQ);
}

const fp6_t *CryptoRelic::Pairing::data() const {
  return e;
}

void CryptoRelic::Pairing::map(const Signature &g1, const GroupPublicKey &g2) {
  pc_map(e, const_cast<ep_st *>(g1.data()), const_cast<ep2_st *>(g2.data()));
}

bool CryptoRelic::Proof::assign(const std::pair<std::string, std::string> &s) {
  return first.assign(s.first) && second.assign(s.second);
}

std::pair<std::string, std::string> CryptoRelic::Proof::toString() const {
  return std::make_pair(first.toString(), second.toString());
}

void CryptoRelic::initCrypto() {
  if (core_init() != RLC_OK) {
    core_clean();
    assert(false);
  }
  if (pc_param_set_any() != RLC_OK) {
    core_clean();
    assert(false);
  }
}
}
}