#include "azure_secret.hpp"
#include "duckdb/main/extension_util.hpp"
#include <azure/identity/azure_cli_credential.hpp>
#include <azure/identity/chained_token_credential.hpp>
#include <azure/identity/default_azure_credential.hpp>
#include <azure/identity/environment_credential.hpp>
#include <azure/identity/managed_identity_credential.hpp>
#include <azure/storage/blobs.hpp>

namespace duckdb {

static string TryGetStringParam(CreateSecretInput &input, const string &param_name) {
	auto param_lookup = input.options.find(param_name);
	if (param_lookup != input.options.end()) {
		return param_lookup->second.ToString();
	} else {
		return "";
	}
}

static unique_ptr<BaseSecret> CreateAzureSecretFromConfig(ClientContext &context, CreateSecretInput &input) {
	string connection_string = TryGetStringParam(input, "connection_string");
	string account_name = TryGetStringParam(input, "account_name");

	auto scope = input.scope;
	if (scope.empty()) {
		scope.push_back("azure://");
		scope.push_back("az://");
	}

	auto result = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);

	//! Add connection string
	if (!connection_string.empty()) {
		result->secret_map["connection_string"] = connection_string;
	}

	// Add account_id
	if (!account_name.empty()) {
		result->secret_map["account_name"] = account_name;
	}

	//! Connection string may hold sensitive data: it should be redacted
	result->redact_keys.insert("connection_string");

	return std::move(result);
}

static unique_ptr<BaseSecret> CreateAzureSecretFromCredentialChain(ClientContext &context, CreateSecretInput &input) {
	string chain = TryGetStringParam(input, "chain");
	string account_name = TryGetStringParam(input, "account_name");
	string azure_endpoint = TryGetStringParam(input, "azure_endpoint");

	auto scope = input.scope;
	if (scope.empty()) {
		scope.push_back("azure://");
		scope.push_back("az://");
	}

	auto result = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);

	// Add config to kv secret
	if (input.options.find("chain") != input.options.end()) {
		result->secret_map["chain"] = TryGetStringParam(input, "chain");
	}
	if (input.options.find("account_name") != input.options.end()) {
		result->secret_map["account_name"] = TryGetStringParam(input, "account_name");
	}
	if (input.options.find("azure_endpoint") != input.options.end()) {
		result->secret_map["azure_endpoint"] = TryGetStringParam(input, "azure_endpoint");
	}

	return std::move(result);
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
	connection_string_function.named_parameters["account_name"] = LogicalType::VARCHAR;
	ExtensionUtil::RegisterFunction(instance, connection_string_function);

	// Register the credential_chain secret provider
	CreateSecretFunction cred_chain_function = {type, "credential_chain", CreateAzureSecretFromCredentialChain};
	cred_chain_function.named_parameters["chain"] = LogicalType::VARCHAR;
	cred_chain_function.named_parameters["account_name"] = LogicalType::VARCHAR;
	cred_chain_function.named_parameters["azure_endpoint"] = LogicalType::VARCHAR;
	ExtensionUtil::RegisterFunction(instance, cred_chain_function);
}

} // namespace duckdb
