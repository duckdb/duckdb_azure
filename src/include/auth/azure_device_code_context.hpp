#pragma once

#include "auth/azure_device_code_credential.hpp"
#include "duckdb/main/client_context_state.hpp"
#include <shared_mutex>
#include <string>
#include <utility>

namespace duckdb {
class AzureDeviceCodeClientContextState final : public ClientContextState {
public:
	const AzureDeviceCodeInfo device_code_info;
	// Access to this attributes should always be protected by firstly acquiring the lock.
	AzureOAuthAccessToken cache_token;

	AzureDeviceCodeClientContextState(AzureDeviceCodeInfo device_code_info)
	    : device_code_info(std::move(device_code_info)) {
	}

	static std::string BuildContextKey(const std::string &secret_name) {
		return "azure:device_codes:" + secret_name;
	}

public: // mutex API
	void lock() {
		cache_token_mutex.lock();
	}
	bool try_lock() {
		return cache_token_mutex.try_lock();
	}
	void unlock() {
		cache_token_mutex.unlock();
	}
	void lock_shared() {
		cache_token_mutex.lock_shared();
	}
	bool try_lock_shared() {
		return cache_token_mutex.try_lock_shared();
	}
	void unlock_shared() {
		cache_token_mutex.unlock_shared();
	}

private:
	std::shared_timed_mutex cache_token_mutex;
};
} // namespace duckdb