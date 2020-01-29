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
#include <spdlog/sinks/dist_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>

#ifdef _WIN32
#include <spdlog/sinks/wincolor_sink.h>
#else

#include <spdlog/sinks/ansicolor_sink.h>

#endif

#if defined(_DEBUG) && defined(_MSC_VER)
#include <spdlog/sinks/msvc_sink.h>
#endif  // _DEBUG && _MSC_VER

fetch::consensus::Logger::Logger(std::string section) : section_{std::move(section)} {
  std::string log_name{fetch::consensus::Logger::logger_name};
  logger_ = spdlog::get(log_name);

  if (logger_ == nullptr) {
#ifdef _WIN32
    auto color_sink = std::make_shared<spdlog::sinks::wincolor_stdout_sink_mt>();
#else
    auto color_sink = std::make_shared<spdlog::sinks::ansicolor_stdout_sink_mt>();
#endif
    auto dist_sink = std::make_shared<spdlog::sinks::dist_sink_st>();
    auto rotating_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("log.txt", 1024 * 1024 * 10, 10);
    dist_sink->add_sink(color_sink);
    dist_sink->add_sink(rotating_sink);
#if defined(_DEBUG) && defined(_MSC_VER)
    auto debug_sink = std::make_shared<spdlog::sinks::msvc_sink_st>();
    dist_sink->add_sink(debug_sink);
#endif  // _DEBUG && _MSC_VER
    logger_ = std::make_shared<spdlog::logger>(log_name, dist_sink);
    spdlog::register_logger(logger_);
  }
}
