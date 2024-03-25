#pragma once

#include "auth/azure_device_code_credential.hpp"
#include "duckdb/main/client_context_state.hpp"
#include <unordered_map>

namespace duckdb {
class AzureDeviceCodesClientContextState final : public ClientContextState {
public:
	const static std::string CONTEXT_KEY;
	std::unordered_map<std::string, const AzureDeviceCodeInfo> device_code_info_by_secret;
};
} // namespace duckdb