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

#include "network.hpp"
#include "logger.hpp"
#include <iostream>

void asyncReadBuffer(asio::ip::tcp::socket &socket, uint32_t,
                     std::function<void(std::error_code, std::shared_ptr<Buffer>)> handler) {
  auto len = std::make_shared<uint32_t>();
  asio::async_read(socket, asio::buffer(len.get(), sizeof(uint32_t)),
                   [len, handler, &socket](std::error_code ec, std::size_t length) {
                     if (ec) {
                       handler(ec, std::make_shared<Buffer>());
                     } else {
                       assert(length == sizeof(uint32_t));
                       auto buffer = std::make_shared<Buffer>(*len);
                       asio::async_read(socket, asio::buffer(buffer->data(), *len),
                                        [buffer, handler](std::error_code ec, std::size_t) {
                                          if (ec) {
                                            std::cerr << "asyncRead2 error " << ec.value() << std::endl;
                                          }
                                          handler(ec, buffer);
                                        });
                     }
                   });
}

std::error_code writeBuffer(asio::ip::tcp::socket &socket, std::shared_ptr<Buffer> s) {
  std::error_code ec;
  std::vector<asio::const_buffer> buffers;
  uint32_t len = uint32_t(s->size());
  buffers.emplace_back(asio::buffer(&len, sizeof(len)));
  buffers.emplace_back(asio::buffer(s->data(), len));
  asio::write(socket, buffers, asio::transfer_all(), ec);
  return ec;
}

void asyncWriteBuffer(asio::ip::tcp::socket &socket, std::shared_ptr<Buffer> s, uint32_t) {
  std::vector<asio::const_buffer> buffers;
  uint32_t len = uint32_t(s->size());
  buffers.emplace_back(asio::buffer(&len, sizeof(len)));
  buffers.emplace_back(asio::buffer(s->data(), len));
  uint32_t total = len + sizeof(len);
  asio::async_write(socket, buffers,
                    [total, s](std::error_code ec, std::size_t length) {
                      if (ec) {
                        std::cerr << "Grouped Async1 write error, wrote " << length << " expected " << total
                                  << std::endl;
                      }
                    });
}

void asyncWriteBuffer(asio::ip::tcp::socket &socket, std::shared_ptr<Buffer> s, uint32_t,
                      std::function<void(std::error_code, std::size_t length)> handler) {
  std::vector<asio::const_buffer> buffers;
  uint32_t len = uint32_t(s->size());
  buffers.emplace_back(asio::buffer(&len, sizeof(len)));
  buffers.emplace_back(asio::buffer(s->data(), len));
  uint32_t total = len + sizeof(len);
  asio::async_write(socket, buffers,
                    [total, s, handler](std::error_code ec, std::size_t length) {
                      if (ec) {
                        std::cerr << "Grouped Async2 write error, wrote " << length << " expected " << total
                                  << std::endl;
                      } else {
                        handler(ec, length);
                      }
                    });
}
