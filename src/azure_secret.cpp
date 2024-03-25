#include "azure_secret.hpp"
#include "azure_dfs_filesystem.hpp"
#include "duckdb/common/types.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/common/unique_ptr.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/main/secret/secret.hpp"
#include <azure/identity/azure_cli_credential.hpp>
#include <azure/identity/chained_token_credential.hpp>
#include <azure/identity/default_azure_credential.hpp>
#include <azure/identity/environment_credential.hpp>
#include <azure/identity/managed_identity_credential.hpp>

namespace duckdb {
constexpr auto COMMON_OPTIONS = {
    // Proxy option
    "http_proxy", "proxy_user_name", "proxy_password",
    // Storage account option
    "account_name", "endpoint"};

static void CopySecret(const std::string &key, const CreateSecretInput &input, KeyValueSecret &result) {
	auto val = input.options.find(key);

	if (val != input.options.end()) {
		result.secret_map[key] = val->second;
	}
}

template <typename T>
static void CopySecret(const std::string &key, const CreateSecretInput &input, KeyValueSecret &result,
                       const T &default_value) {
	auto val = input.options.find(key);

	if (val != input.options.end()) {
		result.secret_map[key] = val->second;
	} else {
		result.secret_map[key] = Value(default_value);
	}
}

static void AddDefaultScopes(vector<string> *scope) {
	scope->push_back("azure://");
	scope->push_back("az://");
	scope->push_back(AzureDfsStorageFileSystem::PATH_PREFIX);
}

static void RedactCommonKeys(KeyValueSecret &result) {
	result.redact_keys.insert("proxy_password");
}

static unique_ptr<BaseSecret> CreateAzureSecretFromConfig(ClientContext &context, CreateSecretInput &input) {
	auto scope = input.scope;
	if (scope.empty()) {
		AddDefaultScopes(&scope);
	}

	auto result = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);

	// Manage common option that all secret type share
	for (const auto *key : COMMON_OPTIONS) {
		CopySecret(key, input, *result);
	}

	// Manage specific secret option
	CopySecret("connection_string", input, *result);

	// Redact sensible keys
	RedactCommonKeys(*result);
	result->redact_keys.insert("connection_string");

	return std::move(result);
}

static unique_ptr<BaseSecret> CreateAzureSecretFromCredentialChain(ClientContext &context, CreateSecretInput &input) {
	auto scope = input.scope;
	if (scope.empty()) {
		AddDefaultScopes(&scope);
	}

	auto result = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);

	// Manage common option that all secret type share
	for (const auto *key : COMMON_OPTIONS) {
		CopySecret(key, input, *result);
	}

	// Manage specific secret option
	CopySecret("chain", input, *result);

	// Redact sensible keys
	RedactCommonKeys(*result);

	return std::move(result);
}

static unique_ptr<BaseSecret> CreateAzureSecretFromServicePrincipal(ClientContext &context, CreateSecretInput &input) {
	auto scope = input.scope;
	if (scope.empty()) {
		AddDefaultScopes(&scope);
	}

	auto result = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);

	// Manage common option that all secret type share
	for (const auto *key : COMMON_OPTIONS) {
		CopySecret(key, input, *result);
	}

	// Manage specific secret option
	CopySecret("tenant_id", input, *result);
	CopySecret("client_id", input, *result);
	CopySecret("client_secret", input, *result);
	CopySecret("client_certificate_path", input, *result);

	// Redact sensible keys
	RedactCommonKeys(*result);
	result->redact_keys.insert("client_secret");
	result->redact_keys.insert("client_certificate_path");

	return std::move(result);
}

static unique_ptr<BaseSecret> CreateAzureSecretFromDeviceCode(ClientContext &context, CreateSecretInput &input) {
	auto scope = input.scope;
	if (scope.empty()) {
		AddDefaultScopes(&scope);
	}

	auto result = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);

	// Manage common option that all secret type share
	for (const auto *key : COMMON_OPTIONS) {
		CopySecret(key, input, *result);
	}

	// Manage specific secret option
	CopySecret("tenant_id", input, *result);
	CopySecret("client_id", input, *result);
	CopySecret("oauth_scopes", input, *result, "https://storage.azure.com/.default");

	// Redact sensible keys
	RedactCommonKeys(*result);

	return std::move(result);
}

static void RegisterCommonSecretParameters(CreateSecretFunction &function) {
	// Register azure common parameters
	function.named_parameters["account_name"] = LogicalType::VARCHAR;
	function.named_parameters["endpoint"] = LogicalType::VARCHAR;

	// Register proxy parameters
	function.named_parameters["http_proxy"] = LogicalType::VARCHAR;
	function.named_parameters["proxy_user_name"] = LogicalType::VARCHAR;
	function.named_parameters["proxy_password"] = LogicalType::VARCHAR;
}

void CreateAzureSecretFunctions::Register(DatabaseInstance &instance) {
	string type = "azure";

	// Register the new type
	SecretType secret_type;
	secret_type.name = type;
	secret_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	secret_type.default_provider = "config";
	ExtensionUtil::RegisterSecretType(instance, secret_type);

	// Register the connection string secret provider
	CreateSecretFunction connection_string_function = {type, "config", CreateAzureSecretFromConfig};
	connection_string_function.named_parameters["connection_string"] = LogicalType::VARCHAR;
	RegisterCommonSecretParameters(connection_string_function);
	ExtensionUtil::RegisterFunction(instance, connection_string_function);

	// Register the credential_chain secret provider
	CreateSecretFunction cred_chain_function = {type, "credential_chain", CreateAzureSecretFromCredentialChain};
	cred_chain_function.named_parameters["chain"] = LogicalType::VARCHAR;
	RegisterCommonSecretParameters(cred_chain_function);
	ExtensionUtil::RegisterFunction(instance, cred_chain_function);

	CreateSecretFunction service_principal_function = {type, "service_principal",
	                                                   CreateAzureSecretFromServicePrincipal};
	service_principal_function.named_parameters["tenant_id"] = LogicalType::VARCHAR;
	service_principal_function.named_parameters["client_id"] = LogicalType::VARCHAR;
	service_principal_function.named_parameters["client_secret"] = LogicalType::VARCHAR;
	service_principal_function.named_parameters["client_certificate_path"] = LogicalType::VARCHAR;
	RegisterCommonSecretParameters(service_principal_function);
	ExtensionUtil::RegisterFunction(instance, service_principal_function);

	CreateSecretFunction device_code_function = {type, "device_code", CreateAzureSecretFromDeviceCode};
	device_code_function.named_parameters["tenant_id"] = LogicalType::VARCHAR;
	device_code_function.named_parameters["client_id"] = LogicalType::VARCHAR;
	device_code_function.named_parameters["oauth_scopes"] = LogicalType::VARCHAR;
	RegisterCommonSecretParameters(device_code_function);
	ExtensionUtil::RegisterFunction(instance, device_code_function);
}

} // namespace duckdb
