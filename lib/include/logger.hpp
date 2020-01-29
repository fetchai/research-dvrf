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

#include <spdlog/fmt/ostr.h>
#include <spdlog/spdlog.h>
#include <string>

enum class LogLevel {
  trace = spdlog::level::level_enum::trace,
  debug = spdlog::level::level_enum::debug,
  info = spdlog::level::level_enum::info,
  warn = spdlog::level::level_enum::warn,
  error = spdlog::level::level_enum::err,
  critical = spdlog::level::level_enum::critical,
  off = spdlog::level::level_enum::off
};

#ifdef TRACE_ON
#define STR_H(x) #x
#define STR_HELPER(x) SPDLOG_STR_H(x)
#define TRACE(logger, ...) logger.trace("[" __FILE__ " line #" SPDLOG_STR_HELPER(__LINE__) "] " __VA_ARGS__)
//#define TRACE_IF(logger, flag, ...) logger.trace_if(flag, "[" __FILE__ " line #" SPDLOG_STR_HELPER(__LINE__) "] " __VA_ARGS__)
#undef STR_H
#undef STR_HELPER
#else
#define TRACE(logger, ...)
#endif
#ifdef DEBUG_ON
#define DEBUG(logger, ...) logger.debug(__VA_ARGS__)
//#define DEBUG_IF(logger, flag, ...) logger.debug_if(flag, __VA_ARGS__)
#else
#define DEBUG(logger, ...)
#endif

namespace fetch {
namespace consensus {
class Logger {
  static constexpr const char *const logger_name = "fetch::logger";
private:
  std::string section_{""};
  std::shared_ptr<spdlog::logger> logger_{nullptr};
public:
  explicit Logger(std::string section);

  std::string section() const noexcept { return section_; }

  template<typename Arg1, typename... Args>
  void log(const LogLevel level, const char *fmt, const Arg1 &arg1, const Args &... args) {
    auto new_fmt = "[{}] " + std::string(fmt);
    logger_->log(static_cast<spdlog::level::level_enum>(level), new_fmt.c_str(), section(),
                 arg1, args...);
  }

  template<typename Arg1, typename... Args>
  void trace(const char *fmt, const Arg1 &arg1, const Args &... args) {
    log(LogLevel::trace, fmt, arg1, args...);
  }

  template<typename Arg1>
  void trace(const Arg1 &arg1) {
    trace("{}", arg1);
  }

  template<typename Arg1, typename... Args>
  void debug(const char *fmt, const Arg1 &arg1, const Args &... args) {
    log(LogLevel::debug, fmt, arg1, args...);
  }

  template<typename Arg1>
  void debug(const Arg1 &arg1) {
    debug("{}", arg1);
  }

  template<typename Arg1, typename... Args>
  void info(const char *fmt, const Arg1 &arg1, const Args &... args) {
    log(LogLevel::info, fmt, arg1, args...);
  }

  template<typename Arg1>
  void info(const Arg1 &arg1) {
    info("{}", arg1);
  }

  template<typename Arg1, typename... Args>
  void warn(const char *fmt, const Arg1 &arg1, const Args &... args) {
    log(LogLevel::warn, fmt, arg1, args...);
  }

  template<typename Arg1>
  void warn(const Arg1 &arg1) {
    warn("{}", arg1);
  }

  template<typename Arg1, typename... Args>
  void error(const char *fmt, const Arg1 &arg1, const Args &... args) {
    log(LogLevel::error, fmt, arg1, args...);
  }

  template<typename Arg1>
  void error(const Arg1 &arg1) {
    error("{}", arg1);
  }

  template<typename Arg1, typename... Args>
  void critical(const char *fmt, const Arg1 &arg1, const Args &... args) {
    log(LogLevel::critical, fmt, arg1, args...);
  }

  template<typename Arg1>
  void critical(const Arg1 &arg1) {
    critical("{}", arg1);
  }

  static void level(const LogLevel level) noexcept {
    spdlog::set_level(static_cast<spdlog::level::level_enum>(level));
  }

};
} // namespace oef
} // namespace fetch
