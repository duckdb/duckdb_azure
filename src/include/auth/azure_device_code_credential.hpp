#pragma once

#include <azure/core/credentials/credentials.hpp>
#include <azure/core/credentials/token_credential_options.hpp>
#include <azure/core/datetime.hpp>
#include <azure/core/http/raw_response.hpp>
#include <azure/core/internal/http/pipeline.hpp>
#include <chrono>
#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_set>

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

namespace duckdb {

class AzureDeviceCodeClientContextState;

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
 * When refresh token is set it seen to be valid for 90 days
 * @see https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens#token-lifetime
 * @see https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#refresh-the-access-token
 */
struct AzureOAuthAccessToken {
	// Number of seconds the included access token is valid for.
	Azure::DateTime expires_at;
	// Issued for the scopes that were requested.
	std::string access_token;
	// Issued if the original scope parameter included offline_access.
	std::string refresh_token;
};

class AzureDeviceCodeCredentialRequester final {
public:
	explicit AzureDeviceCodeCredentialRequester(std::string tenant_id, std::string client_id,
	                                            std::unordered_set<std::string> scopes,
	                                            const Azure::Core::Credentials::TokenCredentialOptions &options =
	                                                Azure::Core::Credentials::TokenCredentialOptions());

	/**
	 * Send a request to get the user & device code
	 */
	AzureDeviceCodeInfo RequestDeviceCode();

private:
	AzureDeviceCodeInfo HandleDeviceAuthorizationResponse(const Azure::Core::Http::RawResponse &response);

private:
	const std::string tenant_id;
	const std::string client_id;
	const std::unordered_set<std::string> scopes;
	const std::string encoded_scopes;

	Azure::Core::Http::_internal::HttpPipeline http_pipeline;
};

class AzureDeviceCodeCredential final : public Azure::Core::Credentials::TokenCredential {
public:
	explicit AzureDeviceCodeCredential(std::string tenant_id, std::string client_id,
	                                   std::unordered_set<std::string> scopes,
	                                   std::shared_ptr<AzureDeviceCodeClientContextState> device_code_context,
	                                   const Azure::Core::Credentials::TokenCredentialOptions &options =
	                                       Azure::Core::Credentials::TokenCredentialOptions());
	Azure::Core::Credentials::AccessToken
	GetToken(Azure::Core::Credentials::TokenRequestContext const &token_request_context,
	         Azure::Core::Context const &context) const override;

private:
	AzureOAuthAccessToken AuthenticatingUser(const AzureDeviceCodeInfo &device_code_info) const;
	AzureOAuthAccessToken RefreshToken(const std::string &refresh_token) const;
	static bool IsFresh(const AzureOAuthAccessToken &token, Azure::DateTime::duration minimum_expiration,
	                    std::chrono::system_clock::time_point now);
	static void ParseJson(const std::string &json_str, AzureOAuthAccessToken *token);

private:
	const std::string tenant_id;
	const std::string client_id;
	const std::unordered_set<std::string> scopes;
	const std::string encoded_scopes;

	const std::shared_ptr<AzureDeviceCodeClientContextState> device_code_context;

	Azure::Core::Http::_internal::HttpPipeline http_pipeline;
};

} // namespace duckdb