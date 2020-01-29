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

#include <assert.h>
#include <iomanip>
#include <set>
#include <sstream>

namespace openssl {

#include <openssl/evp.h>

}

namespace fetch {
namespace consensus {

class SHA3_512 {
  using hash_array = std::array<uint8_t, EVP_MAX_MD_SIZE>;
  hash_array data_;
public:
  explicit SHA3_512(const std::string &msg) {
    auto *mdctx = openssl::EVP_MD_CTX_create();
    assert(mdctx != nullptr);
    openssl::EVP_DigestInit_ex(mdctx, openssl::EVP_sha3_512(), nullptr);
    openssl::EVP_DigestUpdate(mdctx, msg.c_str(), msg.length());
    openssl::EVP_DigestFinal_ex(mdctx, reinterpret_cast<unsigned char *>(data_.data()), nullptr);
    openssl::EVP_MD_CTX_destroy(mdctx);
  }

  std::string toString() const {
    std::stringstream ss;
    for (const auto &d : data_)
      ss << std::hex << std::setw(2) << std::setfill('0') << (int) d;
    return ss.str();
  }

  hash_array &getArray() {
    return data_;
  }
};

}
}