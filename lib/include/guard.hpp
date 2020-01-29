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

#include <utility>

template<typename Functor>
class finally_guard {
  Functor functor_;
  bool active_{true};
public:
  finally_guard(Functor f) : functor_(std::move(f)) {}

  finally_guard(finally_guard &&other) : functor_(std::move(other.functor_)), active_(other.active_) {
    other.active_ = false;
  }

  finally_guard &operator=(finally_guard &&) = delete;

  ~finally_guard() {
    if (active_)
      functor_();
  }

  void dismiss() {
    active_ = false;
  }
};

template<typename F>
finally_guard<typename std::decay<F>::type> finally(F &&f) {
  return {std::forward<F>(f)};
}
