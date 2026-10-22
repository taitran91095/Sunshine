/**
 * @file src/server_commands.h
 * @brief Validation for Apollo-compatible server-command requests.
 */
#pragma once

// standard includes
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace server_commands {
  /**
   * @brief Validate a command index with optional Artemis reserved bytes on an encrypted control stream.
   * @param payload Decrypted Apollo command payload.
   * @param count Number of configured commands.
   * @param protocol Negotiated control protocol; 13 provides authenticated encryption.
   * @return Valid command index, or no value for an invalid request.
   */
  inline std::optional<std::size_t> command_index(std::string_view payload, std::size_t count, int protocol) {
    if (protocol != 13 || (payload.size() != 1 && payload.size() != 4)) {
      return std::nullopt;
    }
    if (payload.size() == 4 && (payload[1] != 0 || payload[2] != 0 || payload[3] != 0)) {
      return std::nullopt;
    }
    const auto index = static_cast<std::uint8_t>(payload.front());
    if (index >= count) {
      return std::nullopt;
    }
    return index;
  }
}
