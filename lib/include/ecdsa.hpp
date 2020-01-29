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

#include "logger.hpp"
#include "sha256.hpp"

#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <assert.h>
#include <utility>
#include <string>

namespace fetch {
namespace consensus {

class ECDSAKey {
  static constexpr int CurveNID = NID_secp256k1;
  static constexpr point_conversion_form_t conversion_ = point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED;

  EC_KEY *keys_;
  fetch::consensus::Logger logger = fetch::consensus::Logger("ecdsa");

public:
  using ECDSASignature = std::vector<uint8_t>;
  ECDSAKey() : keys_{EC_KEY_new_by_curve_name(CurveNID)} {}

  ~ECDSAKey() {
    EC_KEY_free(keys_);
  }

  void generateKeys() {
    EC_KEY_generate_key(keys_);
    assert(EC_KEY_check_key(keys_));
  }

  void setPublicKey(const std::string &publicKeyStr) {
    auto public_key{EC_POINT_new(EC_KEY_get0_group(keys_))};
    EC_POINT_hex2point(EC_KEY_get0_group(keys_), publicKeyStr.c_str(), public_key, nullptr);
    bool check = static_cast<bool>(EC_KEY_set_public_key(keys_, public_key));
    if (!check) {
      logger.error("Failed to set public key!");
    }
    EC_POINT_free(public_key);
  }

  std::string publicKey() const {
    return EC_POINT_point2hex(EC_KEY_get0_group(keys_), EC_KEY_get0_public_key(keys_), conversion_, nullptr);
  }

  void sign(SHA256 message, ECDSASignature &signature) {
    signature.resize(static_cast<uint32_t>(ECDSA_size(keys_)));
    unsigned int sig_size = 0;
    bool check = static_cast<bool>(ECDSA_sign(0, reinterpret_cast<unsigned char *>(message.getArray().data()), 256,
                                              signature.data(), &sig_size, keys_));
    if (!check) {
      logger.error("Failed to sign message {}", message.toString());
    }
    signature.resize(sig_size);
  }

  bool verify(SHA256 message, const ECDSASignature &signature) {
    auto verify = static_cast<int8_t>(ECDSA_verify(0, reinterpret_cast<unsigned char *>(message.getArray().data()), 256,
                                                   signature.data(), static_cast<int>(signature.size()), keys_));
    if (verify == -1) {
      logger.error("ECDSA signature verification returned error");
      return false;
    }
    return verify;
  }
};
}
}