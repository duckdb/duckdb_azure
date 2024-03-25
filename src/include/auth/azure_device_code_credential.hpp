#pragma once

#include <azure/core/credentials/credentials.hpp>
#include <azure/core/credentials/token_credential_options.hpp>
#include <azure/core/http/raw_response.hpp>
#include <azure/core/internal/http/pipeline.hpp>
#include <azure/identity/detail/token_cache.hpp>
#include <azure/identity/detail/client_credential_core.hpp>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_set>

namespace duckdb {

struct AzureDeviceCodeInfo {
	// A long string used to verify the session between the client and the authorization server.
	// The client uses this parameter to request the access token from the authorization server.
	std::string device_code;
	// A short string shown to the user used to identify the session on a secondary device.
	std::string user_code;
	// The URI the user should go to with the user_code in order to sign in.
	std::string verification_uri;
	// The number of seconds before the device_code and user_code expire.
	std::chrono::system_clock::time_point expires_at;
	// The number of seconds the client should wait between polling requests.
	std::chrono::seconds interval;
	// A human-readable string with instructions for the user. This can be localized by including a
	// query parameter in the request of the form ?mkt=xx-XX, filling in the appropriate language
	// culture code.
	std::string message;
};

/**
 * Implement the missing DeviceCodeCredential from the C++ SDK
 * https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code
 *
 * Note: The way this has been develop is also a hack on how the workflow (should) work.
 * In theory the scopes shouldn't be an args of the constructor, they are given when a request
 * call the #GetToken method and we should call a callback that would inform the user that they
 * have to go to an URL and enter the user code.
 * In our case it's hard to prompt the user because when queries are performed we do not known
 * how DuckDB is really being use(cmd, lib...)
 * So we split the way we obtains the user/device code and the token retrieval.
 */
class AzureDeviceCodeCredential final : public Azure::Core::Credentials::TokenCredential {
public:
	explicit AzureDeviceCodeCredential(std::string tenant_id, std::string client_id,
	                                   std::unordered_set<std::string> scopes,
	                                   Azure::Core::Credentials::TokenCredentialOptions const &options =
	                                       Azure::Core::Credentials::TokenCredentialOptions());

	explicit AzureDeviceCodeCredential(std::string tenant_id, std::string client_id,
	                                   std::unordered_set<std::string> scopes, AzureDeviceCodeInfo device_code,
	                                   const Azure::Core::Credentials::TokenCredentialOptions &options =
	                                       Azure::Core::Credentials::TokenCredentialOptions());
	Azure::Core::Credentials::AccessToken
	GetToken(Azure::Core::Credentials::TokenRequestContext const &token_request_context,
	         Azure::Core::Context const &context) const override;

	/**
	 * Send a request to get the user & device code
	 */
	AzureDeviceCodeInfo RequestDeviceCode();

private:
	explicit AzureDeviceCodeCredential(std::string tenant_id, std::string client_id,
	                                   std::unordered_set<std::string> scopes,
	                                   const Azure::Core::Credentials::TokenCredentialOptions &options,
	                                   std::unique_ptr<AzureDeviceCodeInfo> device_code_info);

	AzureDeviceCodeInfo HandleDeviceAuthorizationResponse(const Azure::Core::Http::RawResponse &response);
	Azure::Core::Credentials::AccessToken AuthenticatingUser() const;

private:
	const std::string tenant_id;
	const std::string client_id;
	const std::unordered_set<std::string> scopes;
	const std::string encoded_scopes;
	const std::unique_ptr<AzureDeviceCodeInfo> device_code_info;

	Azure::Identity::_detail::TokenCache token_cache;
	Azure::Core::Http::_internal::HttpPipeline http_pipeline;
};

} // namespace duckdb