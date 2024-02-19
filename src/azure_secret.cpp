#include "azure_secret.hpp"
#include "duckdb/common/unique_ptr.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/main/secret/secret.hpp"
#include <azure/identity/azure_cli_credential.hpp>
#include <azure/identity/chained_token_credential.hpp>
#include <azure/identity/default_azure_credential.hpp>
#include <azure/identity/environment_credential.hpp>
#include <azure/identity/managed_identity_credential.hpp>
#include <azure/storage/blobs.hpp>

namespace duckdb {

static void FillWithAzureProxyInfo(ClientContext &context, CreateSecretInput &input, KeyValueSecret &result) {
	auto http_proxy = input.options.find("http_proxy");
	auto proxy_user_name = input.options.find("proxy_user_name");
	auto proxy_password = input.options.find("proxy_password");

	// Proxy info
	if (http_proxy != input.options.end()) {
		result.secret_map["http_proxy"] = http_proxy->second;
	}
	if (proxy_user_name != input.options.end()) {
		result.secret_map["proxy_user_name"] = proxy_user_name->second;
	}
	if (proxy_password != input.options.end()) {
		result.secret_map["proxy_password"] = proxy_password->second;
		result.redact_keys.insert("proxy_password");
	}
}

static unique_ptr<BaseSecret> CreateAzureSecretFromConfig(ClientContext &context, CreateSecretInput &input) {
	auto connection_string = input.options.find("connection_string");
	auto account_name = input.options.find("account_name");

	auto scope = input.scope;
	if (scope.empty()) {
		scope.push_back("azure://");
		scope.push_back("az://");
	}

	auto result = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);

	FillWithAzureProxyInfo(context, input, *result);

	//! Add connection string
	if (connection_string != input.options.end()) {
		result->secret_map["connection_string"] = connection_string->second;
		//! Connection string may hold sensitive data: it should be redacted
		result->redact_keys.insert("connection_string");
	}

	// Add account_id
	if (account_name != input.options.end()) {
		result->secret_map["account_name"] = account_name->second;
	}

	return std::move(result);
}

static unique_ptr<BaseSecret> CreateAzureSecretFromCredentialChain(ClientContext &context, CreateSecretInput &input) {
	auto chain = input.options.find("chain");
	auto account_name = input.options.find("account_name");
	auto azure_endpoint = input.options.find("azure_endpoint");

	auto scope = input.scope;
	if (scope.empty()) {
		scope.push_back("azure://");
		scope.push_back("az://");
	}

	auto result = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);

	FillWithAzureProxyInfo(context, input, *result);

	// Add config to kv secret
	if (chain != input.options.end()) {
		result->secret_map["chain"] = chain->second;
	}
	if (account_name != input.options.end()) {
		result->secret_map["account_name"] = account_name->second;
	}
	if (azure_endpoint != input.options.end()) {
		result->secret_map["azure_endpoint"] = azure_endpoint->second;
	}

	return std::move(result);
}

static void RegisterCommonSecretParameters(CreateSecretFunction &function) {
	// Register azure common parameters
	function.named_parameters["account_name"] = LogicalType::VARCHAR;

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
	cred_chain_function.named_parameters["azure_endpoint"] = LogicalType::VARCHAR;
	RegisterCommonSecretParameters(cred_chain_function);
	ExtensionUtil::RegisterFunction(instance, cred_chain_function);
}

} // namespace duckdb
