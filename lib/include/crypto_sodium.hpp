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
#include <string>

#include <sodium.h>

namespace fetch {
namespace consensus {

class CryptoSodium {
public:

  class Signature;

  class PrivateKey : public std::array<unsigned char, crypto_core_ristretto255_SCALARBYTES> {
  public:
    using std::array<unsigned char, crypto_core_ristretto255_SCALARBYTES>::operator=;

    PrivateKey();
    PrivateKey(uint32_t num);

    void random();
    void increment();
    bool assign(const std::string &s);
    void setZero();
    void add(const PrivateKey &left, const PrivateKey &right);
    void sub(const PrivateKey &left, const PrivateKey &right);
    void mult(const PrivateKey &left, const PrivateKey &right);
    void inv(const PrivateKey &inv);
    void negate(const PrivateKey &neg);
    void pow(const PrivateKey &in, int32_t pow);
    void div(const PrivateKey &num, const PrivateKey &denom);
    bool isZero() const;
    std::string toString() const;

    // For ZKP
    void setHashOf(const Signature &generator, const Signature &Hm, const Signature &publicKey, const Signature &sig,
                   const Signature &com1, const Signature &com2);
  };

  class Signature : public std::array<unsigned char, crypto_core_ristretto255_BYTES> {
  public:
    Signature();
    Signature(uint32_t num);

    bool assign(const std::string &s);
    void mult(const Signature &left, const PrivateKey &right);
    void add(const Signature &left, const Signature &right);
    void sub(const Signature &left, const Signature &right);
    void setZero();
    void hashAndMap(const std::string &payload);
    std::string toString() const;
    bool isZero() const;
  };

  using GroupPublicKey = Signature;

  /// Class for ZKP
  /// @{
  class Proof : public std::pair<PrivateKey, PrivateKey> {
  public:
    Proof() = default;

    std::pair<std::string, std::string> toString() const;
    bool assign(const std::pair<std::string, std::string> &s);
  };
  /// @}

  /// Helper functions
  /// @{
  static void initCrypto();
  static void setGenerator(Signature &group_g);
  static void setGenerators(Signature &group_g, Signature &group_h);
  /// @}
};
}
}