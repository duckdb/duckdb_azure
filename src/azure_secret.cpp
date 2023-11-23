#include "azure_secret.hpp"
#include "duckdb/main/extension_util.hpp"
#include <azure/identity/azure_cli_credential.hpp>
#include <azure/identity/chained_token_credential.hpp>
#include <azure/identity/default_azure_credential.hpp>
#include <azure/identity/environment_credential.hpp>
#include <azure/identity/managed_identity_credential.hpp>
#include <azure/storage/blobs.hpp>

namespace duckdb {

// TODO DEDUP
static Azure::Identity::ChainedTokenCredential::Sources
CreateCredentialChainFromSetting(const string &credential_chain) {
	auto chain_list = StringUtil::Split(credential_chain, ';');
	Azure::Identity::ChainedTokenCredential::Sources result;

	for (const auto &item : chain_list) {
		if (item == "cli") {
			result.push_back(std::make_shared<Azure::Identity::AzureCliCredential>());
		} else if (item == "managed_identity") {
			result.push_back(std::make_shared<Azure::Identity::ManagedIdentityCredential>());
		} else if (item == "env") {
			result.push_back(std::make_shared<Azure::Identity::EnvironmentCredential>());
		} else if (item == "default") {
			result.push_back(std::make_shared<Azure::Identity::DefaultAzureCredential>());
		} else if (item != "none") {
			throw InvalidInputException("Unknown credential provider found: " + item);
		}
	}

	return result;
}

static unique_ptr<BaseSecret> CreateAzureSecretFromConnectionString(ClientContext &context, CreateSecretInput &input) {
	string connection_string;

	for (const auto &named_param : input.named_parameters) {
		if (named_param.first == "connection_string") {
			connection_string = named_param.second.ToString();
		} else {
			throw InternalException("Invalid parameter passed to CreateAzureSecretFromConnectionString: " +
			                        named_param.first);
		}
	}

	// Set scope to user provided scope or the default
	auto scope = input.scope;
	if (scope.empty()) {
		scope.push_back("azure://");
		scope.push_back("az://");
	}

	auto secret = make_uniq<AzureSecret>(scope, input.type, input.provider, input.name);
	secret->SetConnectionString(connection_string);
	return secret;
}

static unique_ptr<BaseSecret> CreateAzureSecretFromCredentialChain(ClientContext &context, CreateSecretInput &input) {
	string credential_chain;
	string account_name;
	string azure_endpoint;
	string token_string;
	string token_expires_on;
	int token_validity_minutes = -1;

	for (const auto &named_param : input.named_parameters) {
		if (named_param.first == "credential_chain") {
			credential_chain = named_param.second.ToString();
		} else if (named_param.first == "account_name") {
			account_name = named_param.second.ToString();
		} else if (named_param.first == "azure_endpoint") {
			azure_endpoint = named_param.second.ToString();
		} else if (named_param.first == "token_validity_minutes") {
			if (!named_param.second.ToString().empty()) {
				token_validity_minutes = Value(named_param.second.ToString()).DefaultCastAs(LogicalType::INTEGER).GetValue<int>();
			}
		} else {
			throw InternalException("Invalid parameter passed to CreateAzureSecretFromCredentialChain: " +
			                        named_param.first);
		}
	}

	// TODO: unclear if this works
	if (token_validity_minutes == -1) {
		token_validity_minutes = 60 * 24 * 30; // 30 Days TODO: make global option
	}

	// Build credential chain, from last to first
	Azure::Identity::ChainedTokenCredential::Sources chain;
	if (!credential_chain.empty()) {
		chain = CreateCredentialChainFromSetting(credential_chain);
	} else {
		chain = CreateCredentialChainFromSetting("default");
	}

	if (!chain.empty()) {
		// A set of credentials providers was passed, construct a token from it
		auto chainedTokenCredential = std::make_shared<Azure::Identity::ChainedTokenCredential>(chain);
		Azure::Core::Credentials::TokenRequestContext token_request_context;
		token_request_context.Scopes = {"https://storage.azure.com/.default"};
		token_request_context.MinimumExpiration = std::chrono::minutes(1);
		Azure::Core::Context azure_context;
		auto token = chainedTokenCredential->GetToken(token_request_context, azure_context);
		token_string = token.Token;
		token_expires_on = token.ExpiresOn.ToString(Azure::DateTime::DateFormat::Rfc3339);
	} else if (!account_name.empty()) {
		// TODO unauthenticated path should be implemented: this allows specifying the other params (account name/endpoint)
		// 		per scope, but without needing a valid token.
		throw NotImplementedException("Unauth secrets are weird but useful?");
	} else {
		throw InvalidInputException(
		    "No valid Azure credentials found, use either the azure_connection_string or azure_account_name");
	}

	// Set scope to user provided scope or the default
	auto scope = input.scope;
	if (scope.empty()) {
		scope.push_back("azure://");
		scope.push_back("az://");
	}

	auto secret = make_uniq<AzureSecret>(scope, input.type, input.provider, input.name);
	secret->SetCredentialChainToken(credential_chain, account_name, token_string, token_expires_on, azure_endpoint);
	return secret;
}

void CreateAzureSecretFunctions::Register(DatabaseInstance &instance) {
	string type = "azure";

	// Register the new type
	SecretType secret_type;
	secret_type.name = type;
	secret_type.deserializer = BaseKeyValueSecret::Deserialize<AzureSecret>;
	secret_type.default_provider = "connection_string";
	ExtensionUtil::RegisterSecretType(instance, secret_type);

	// Register the connection string secret provider
	CreateSecretFunction connection_string_function = {type, "connection_string", CreateAzureSecretFromConnectionString};
	connection_string_function.named_parameters["connection_string"] = LogicalType::VARCHAR;
	ExtensionUtil::RegisterFunction(instance, connection_string_function);

	// Register the credential_chain secret provider
	CreateSecretFunction cred_chain_function = {type, "credential_chain", CreateAzureSecretFromCredentialChain};
	cred_chain_function.named_parameters["credential_chain"] = LogicalType::VARCHAR;
	cred_chain_function.named_parameters["account_name"] = LogicalType::VARCHAR;
	cred_chain_function.named_parameters["azure_endpoint"] = LogicalType::VARCHAR;
	cred_chain_function.named_parameters["token_validity_minutes"] = LogicalType::VARCHAR;
	ExtensionUtil::RegisterFunction(instance, cred_chain_function);


}

} // namespace duckdb
