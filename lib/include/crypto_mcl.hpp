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

#include "curve_type.hpp"

#ifdef BLS12
#include <mcl/bls12_381.hpp>
namespace bn = mcl::bls12;
#endif
#ifdef BN384
#include <mcl/bn384.hpp>
namespace bn = mcl::bn384;
#endif
#ifdef BN512
#include <mcl/bn512.hpp>
namespace bn = mcl::bn512;
#endif
#if !defined(BLS12) && !defined(BN384) && !defined(BN512)

#include "mcl/bn256.hpp"

namespace bn = mcl::bn256;
#endif

namespace fetch {
namespace consensus {

class CryptoMcl {
public:

  class Signature;

  class PrivateKey : public bn::Fr {
  public:
    PrivateKey();
    PrivateKey(uint32_t num);

    void random();
    void increment();
    std::string toString() const;
    bool assign(const std::string &s);
    void setZero();
    void add(const PrivateKey &left, const PrivateKey &right);
    void sub(const PrivateKey &left, const PrivateKey &right);
    void mult(const PrivateKey &left, const PrivateKey &right);
    void inv(const PrivateKey &inv);
    void negate(const PrivateKey &neg);
    void pow(const PrivateKey &left, uint32_t pow);
    void div(const PrivateKey &left, const PrivateKey &right);

    // For ZKP
    void setHashOf(const Signature &generator, const Signature &Hm, const Signature &publicKey, const Signature &sig,
                   const Signature &com1, const Signature &com2);
  };

  class Signature : public bn::G1 {
  public:
    Signature();

    void setZero();
    bool assign(const std::string &s);
    void mult(const Signature &left, const PrivateKey &right);
    void add(const Signature &left, const Signature &right);
    void hashAndMap(const std::string &payload);
    std::string toString() const;
  };

  class GroupPublicKey : public bn::G2 {
  public:
    GroupPublicKey();

    void setZero();
    bool assign(const std::string &s);
    void mult(const GroupPublicKey &left, const PrivateKey &right);
    void add(const GroupPublicKey &left, const GroupPublicKey &right);
    void hashAndMap(const std::string &payload);
    std::string toString() const;
  };

  /// Class for computing pairings
  /// @{
  class Pairing : public bn::Fp12 {
  public:
    Pairing();

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


  /// Helper functions - setGenerators need to be templated for the different generator
  /// types in BLS and Modified BLS
  /// @{
  static void initCrypto();

  template<class Generator>
  static void setGenerator(Generator &group_g) {
    group_g.setZero();
    group_g.hashAndMap("FetchAi - Crypto Generator G" + std::string(typeid(group_g).name()));
  }

  template<class Generator>
  static void setGenerators(Generator &group_g, Generator &group_h) {
    setGenerator(group_g);

    group_h.setZero();
    group_h.hashAndMap("FetchAi - Crypto Generator H" + std::string(typeid(group_h).name()));
  }
  /// @}
};
}
}