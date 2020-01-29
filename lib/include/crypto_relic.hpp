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

#include <string>
#include <assert.h>

extern "C" {
#include <relic.h>
#include <sodium.h>
}

namespace fetch {
namespace consensus {

class CryptoRelic {
public:

  class Signature;

  class PrivateKey {
  private:
    bn_t bn, n;
  public:
    PrivateKey();
    explicit PrivateKey(uint32_t num);
    void operator=(const PrivateKey &right);
    bool operator==(const PrivateKey &right) const;
    bool operator!=(const PrivateKey &right) const;
    void setZero();
    const bn_st *data() const;
    void random();
    void increment();
    std::string toString() const;
    bool assign(const std::string &s);
    void add(const PrivateKey &left, const PrivateKey &right);
    void sub(const PrivateKey &left, const PrivateKey &right);
    bool isZero() const;
    void mult(const PrivateKey &left, const PrivateKey &right);
    void div(const PrivateKey &left, const PrivateKey &right);
    void pow(const PrivateKey &left, uint32_t pow);
    void inv(const PrivateKey &inv);
    void negate(const PrivateKey &neg);

    // For ZKP
    void setHashOf(const Signature &generator, const Signature &Hm, const Signature &publicKey, const Signature &sig,
                   const Signature &com1, const Signature &com2);
  };

  class Signature {
  private:
    g1_t g1;
  public:
    Signature();
    explicit Signature(bool isGenerator);
    void operator=(const Signature &right);
    bool operator==(const Signature &right) const;
    bool operator!=(const Signature &right) const;
    void setZero();
    void fromCStr(const uint8_t *num, int size);
    const ep_st *data() const;
    bool assign(const std::string &s);
    void mult(const Signature &left, const PrivateKey &right);
    void add(const Signature &left, const Signature &right);
    void hashAndMap(const std::string &payload);
    std::string toString() const;
    bool isZero() const;
  };

  class GroupPublicKey {
  private:
    g2_t g2;
  public:
    GroupPublicKey();
    explicit GroupPublicKey(bool isGenerator);
    void operator=(const GroupPublicKey &right);
    bool operator==(const GroupPublicKey &right) const;
    bool operator!=(const GroupPublicKey &right) const;
    void setZero();
    const ep2_st *data() const;
    bool assign(const std::string &s);
    void mult(const GroupPublicKey &left, const PrivateKey &right);
    void add(const GroupPublicKey &left, const GroupPublicKey &right);
    std::string toString() const;
    bool isZero() const;
  };

  /// For computing pairings
  /// @{
  class Pairing {
  private:
    gt_t e;
  public:
    Pairing();
    bool operator==(const Pairing &e2);
    bool operator!=(const Pairing &e2);
    const fp6_t *data() const;
    void map(const Signature &g1, const GroupPublicKey &g2);
  };
  /// @}

  /// Class for ZKP
  /// @{
  class Proof : public std::pair<PrivateKey, PrivateKey> {
  public:
    Proof() = default;

    std::pair<std::string, std::string> toString() const;
    bool assign(const std::pair<std::string, std::string> &s);
  };
  /// @}

  /// Helper functions- setGenerators need to be templated for the different generator
  /// types in BLS and Modified BLS
  /// @{
  static void initCrypto();

  template<class Generator>
  static void setGenerator(Generator &group_g) {
    Generator tmp(true);
    group_g = tmp;
  }

  template<class Generator>
  static void setGenerators(Generator &group_g, Generator &group_h) {
    setGenerator(group_g);

    PrivateKey m1{20};
    group_h.mult(group_g, m1);
  }
  /// @}
};

}
}