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

#include <openssl/sha.h>

}

namespace fetch {
namespace consensus {

class SHA512 {
  using hash_array = std::array<uint8_t, SHA512_DIGEST_LENGTH>;
  hash_array data_;
public:
  explicit SHA512(const std::string &msg) {
    openssl::SHA512_CTX sha512;
    openssl::SHA512_Init(&sha512);
    openssl::SHA512_Update(&sha512, msg.c_str(), msg.length());
    openssl::SHA512_Final(reinterpret_cast<unsigned char *>(data_.data()), &sha512);
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