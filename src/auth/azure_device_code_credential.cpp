#include "auth/azure_device_code_credential.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/string_util.hpp"
#include <algorithm>
#include <azure/core/context.hpp>
#include <azure/core/credentials/credentials.hpp>
#include <azure/core/datetime.hpp>
#include <azure/core/http/http.hpp>
#include <azure/core/internal/environment.hpp>
#include <azure/core/internal/json/json.hpp>
#include <azure/core/http/http_status_code.hpp>
#include <azure/core/internal/strings.hpp>
#include <azure/core/io/body_stream.hpp>
#include <azure/core/url.hpp>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace duckdb {

// TODO https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#refresh-the-access-token
// TODO replace AccessToken by this class ??
struct RequestDeviceCodeResponse {};

struct HttpResponseError {
	std::string error;
	std::string error_description;
	std::vector<std::int32_t> error_codes;
	std::string timestamp;
	std::string trace_id;
	std::string correlation_id;
	std::string error_uri;
};

static void ParseJson(const std::string &json_str, AzureDeviceCodeInfo *response) {
	auto now = std::chrono::system_clock::now();
	try {
		auto json = Azure::Core::Json::_internal::json::parse(json_str);

		response->device_code = json.at("device_code").get<std::string>();
		response->user_code = json.at("user_code").get<std::string>();
		response->verification_uri = json.at("verification_uri").get<std::string>();
		response->expires_at = now + std::chrono::seconds(json.at("expires_in").get<std::int32_t>());
		response->interval = std::chrono::seconds(json.at("interval").get<std::int32_t>());
		response->message = json.at("message").get<std::string>();
	} catch (const Azure::Core::Json::_internal::json::out_of_range &ex) {
		throw IOException("[AzureDeviceCodeCredential] Failed to parse Azure response '%s'", ex.what());
	} catch (const Azure::Core::Json::_internal::json::exception &ex) {
		throw IOException("[AzureDeviceCodeCredential] Failed to parse JSON Azure response '%s'", ex.what());
	}
}
static void ParseJson(const std::string &json_str, Azure::Core::Credentials::AccessToken *token) {
	try {
		auto json = Azure::Core::Json::_internal::json::parse(json_str);

		token->Token = json.at("access_token").get<std::string>();
		token->ExpiresOn = Azure::DateTime(std::chrono::system_clock::now()) +
		                   std::chrono::seconds(json.at("expires_in").get<std::int32_t>());
	} catch (const Azure::Core::Json::_internal::json::out_of_range &ex) {
		throw IOException("[AzureDeviceCodeCredential] Failed to parse Azure response '%s'", ex.what());
	} catch (const Azure::Core::Json::_internal::json::exception &ex) {
		throw IOException("[AzureDeviceCodeCredential] Failed to parse JSON Azure response '%s'", ex.what());
	}
}

static bool TryParseJson(const std::string &json_str, HttpResponseError *error) {
	try {
		auto json = Azure::Core::Json::_internal::json::parse(json_str);

		error->error = json.at("error").get<std::string>();
		error->error_description = json.at("error_description").get<std::string>();
		error->error_codes = json.at("error_codes").get<std::vector<std::int32_t>>();
		error->timestamp = json.at("timestamp").get<std::string>();
		error->trace_id = json.at("trace_id").get<std::string>();
		error->correlation_id = json.at("correlation_id").get<std::string>();
		error->error_uri = json.at("error_uri").get<std::string>();
		return true;
	} catch (...) {
	}
	return false;
}

static std::string EncodeScopes(const std::unordered_set<std::string> &scopes) {
	// The result
	std::string result;

	// If the input isn't empty, append the first element. We do this so we
	// don't need to introduce an if into the loop.
	if (scopes.size() > 0) {
		auto it = scopes.begin();
		const auto end = scopes.end();
		result = *it;

		// Append the remaining input components, after the first
		while (++it != end) {
			result += ' ' + *it;
		}
	}
	return Azure::Core::Url::Encode(result);
}

static std::string CacheScopeString(const std::vector<std::string> &scopes) {
	switch (scopes.size()) {
	case 0:
		return "";

	case 1:
		return scopes[0];

	default: {
		std::string result;
		auto copy_scopes = scopes;
		std::sort(copy_scopes.begin(), copy_scopes.end());
		for (const auto &scope : copy_scopes) {
			result += scope;
		}
		return result;
	}
	}
}

AzureDeviceCodeCredentialRequester::AzureDeviceCodeCredentialRequester(
    std::string tenant_id, std::string client_id, std::unordered_set<std::string> scopes_p,
    const Azure::Core::Credentials::TokenCredentialOptions &options)
    : tenant_id(std::move(tenant_id)), client_id(std::move(client_id)), scopes(std::move(scopes_p)),
      encoded_scopes(EncodeScopes(scopes)), http_pipeline(options, "identity", "DuckDB", {}, {}) {
}

AzureDeviceCodeInfo AzureDeviceCodeCredentialRequester::RequestDeviceCode() {
	const std::string url = "https://login.microsoftonline.com/" + tenant_id + "/oauth2/v2.0/devicecode";
	const std::string body = "client_id=" + Azure::Core::Url::Encode(client_id) + "&scope=" + encoded_scopes;
	Azure::Core::IO::MemoryBodyStream body_stream(reinterpret_cast<const std::uint8_t *>(body.data()), body.size());

	Azure::Core::Http::Request http_request(Azure::Core::Http::HttpMethod::Post, Azure::Core::Url(url), &body_stream);
	http_request.SetHeader("Content-Type", "application/x-www-form-urlencoded");
	http_request.SetHeader("Content-Length", std::to_string(body.size()));
	http_request.SetHeader("Accept", "application/json");

	auto response = http_pipeline.Send(http_request, Azure::Core::Context());
	return HandleDeviceAuthorizationResponse(*response);
}

AzureDeviceCodeInfo
AzureDeviceCodeCredentialRequester::HandleDeviceAuthorizationResponse(const Azure::Core::Http::RawResponse &response) {
	const auto &response_body = response.GetBody();
	const auto response_body_str = std::string(response_body.begin(), response_body.end());
	if (response.GetStatusCode() == Azure::Core::Http::HttpStatusCode::Ok) {
		AzureDeviceCodeInfo parsed_response;
		ParseJson(std::string(response_body.begin(), response_body.end()), &parsed_response);
		return parsed_response;
	} else {
		throw IOException(
		    "[AzureDeviceCodeCredentialRequester] Failed to retrieve devicecode HTTP code: %d, details: %s",
		    response.GetStatusCode(), response_body_str);
	}
}

AzureDeviceCodeCredential::AzureDeviceCodeCredential(std::string tenant_id, std::string client_id,
                                                     std::unordered_set<std::string> scopes_p,
                                                     AzureDeviceCodeInfo device_code_info,
                                                     const Azure::Core::Credentials::TokenCredentialOptions &options)
    : Azure::Core::Credentials::TokenCredential("DeviceCodeCredential"), tenant_id(std::move(tenant_id)),
      client_id(std::move(client_id)), scopes(std::move(scopes_p)), device_code_info(std::move(device_code_info)),
      http_pipeline(options, "identity", "DuckDB", {}, {}) {
}

Azure::Core::Credentials::AccessToken AzureDeviceCodeCredential::AuthenticatingUser() const {
	// Check if it still possible to retrieve a token!
	auto now = std::chrono::system_clock::now();
	if (now >= device_code_info.expires_at) {
		throw IOException("[AzureDeviceCodeCredential] Your previous credential has already expired please "
		                  "renew it by calling `SELECT * FROM azure_devicecode('<secret name>')`;");
	}

	const std::string url = "https://login.microsoftonline.com/" + tenant_id + "/oauth2/v2.0/token";
	const std::string body = "grant_type=urn:ietf:params:oauth:grant-type:device_code"
	                         "&client_id=" +
	                         Azure::Core::Url::Encode(client_id) + "&device_code=" + device_code_info.device_code;
	Azure::Core::IO::MemoryBodyStream body_stream(reinterpret_cast<const std::uint8_t *>(body.data()), body.size());

	Azure::Core::Http::Request http_request(Azure::Core::Http::HttpMethod::Post, Azure::Core::Url(url), &body_stream);
	http_request.SetHeader("Content-Type", "application/x-www-form-urlencoded");
	http_request.SetHeader("Content-Length", std::to_string(body.size()));
	http_request.SetHeader("Accept", "application/json");

	while (true) {
		auto response = http_pipeline.Send(http_request, Azure::Core::Context());
		const auto &response_body = response->GetBody();
		const auto response_body_str = std::string(response_body.begin(), response_body.end());

		switch (response->GetStatusCode()) {
		case Azure::Core::Http::HttpStatusCode::Ok: {
			Azure::Core::Credentials::AccessToken token;
			ParseJson(response_body_str, &token);
			return token;
		} break;

		default: {
			HttpResponseError error;
			TryParseJson(response_body_str, &error);
			if ("authorization_pending" == error.error) {
				// Wait before retry
				std::this_thread::sleep_for(device_code_info.interval);
			} else if ("authorization_declined" == error.error) {
				throw IOException("[AzureDeviceCodeCredential] Failed to retrieve user token, end user denied the "
				                  "authorization request. (error msg: %s)",
				                  response_body_str);
			} else if ("bad_verification_code" == error.error) {
				throw IOException(
				    "[AzureDeviceCodeCredential] Failed to retrieve recognized device code. (error msg: %s)",
				    response_body_str);
			} else if ("expired_token" == error.error) {
				throw IOException(
				    "[AzureDeviceCodeCredential] Failed to retrieve user token already expired. (error msg: %s)",
				    response_body_str);
			} else {
				throw IOException("[AzureDeviceCodeCredential] Unexpected error: %s", response_body_str);
			}
		} break;
		}
	}
}

Azure::Core::Credentials::AccessToken
AzureDeviceCodeCredential::GetToken(Azure::Core::Credentials::TokenRequestContext const &token_request_context,
                                    Azure::Core::Context const &context) const {
	using Azure::Core::_internal::StringExtensions;

	if (device_code_info.device_code.empty()) {
		throw IOException("[AzureDeviceCodeCredential] No device/user code register did you call `SELECT * FROM "
		                  "azure_devicecode('<secret name>')`;");
	}

	if (!token_request_context.TenantId.empty() &&
	    !StringExtensions::LocaleInvariantCaseInsensitiveEqual(token_request_context.TenantId, tenant_id)) {

		throw IOException(
		    "[AzureDeviceCodeCredential] The current credential is not configured to acquire tokens for tenant '%s'.",
		    token_request_context.TenantId);
	}
	for (const auto &scope : token_request_context.Scopes) {
		if (scopes.find(scope) == scopes.end()) {
			throw IOException("[AzureDeviceCodeCredential] The required scope %s is not part of the requested scope, "
			                  "please check secret defintion.",
			                  scope);
		}
	}
	auto request_scopes = token_request_context.Scopes;
	std::sort(request_scopes.begin(), request_scopes.end());

	return token_cache.GetToken(CacheScopeString(token_request_context.Scopes), token_request_context.TenantId,
	                            token_request_context.MinimumExpiration, [&]() { return AuthenticatingUser(); });
}

} // namespace duckdb