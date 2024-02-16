#include "azure_storage_account_client.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/enums/statement_type.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_opener.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

#include <azure/core/credentials/token_credential_options.hpp>
#include <azure/identity/azure_cli_credential.hpp>
#include <azure/identity/chained_token_credential.hpp>
#include <azure/identity/client_certificate_credential.hpp>
#include <azure/identity/client_secret_credential.hpp>
#include <azure/identity/default_azure_credential.hpp>
#include <azure/identity/environment_credential.hpp>
#include <azure/identity/managed_identity_credential.hpp>
#include <azure/storage/blobs/blob_options.hpp>
#include <azure/storage/blobs/blob_service_client.hpp>

#include <memory>
#include <string>

namespace duckdb {
const static std::string DEFAULT_ENDPOINT = "blob.core.windows.net";

static std::string TryGetCurrentSetting(FileOpener *opener, const std::string &name) {
	Value val;
	if (FileOpener::TryGetCurrentSetting(opener, name, val)) {
		return val.ToString();
	}
	return "";
}

static Azure::Storage::Blobs::BlobClientOptions
ToBlobClientOptions(const Azure::Core::Http::Policies::TransportOptions &transport_options) {
	Azure::Storage::Blobs::BlobClientOptions options;
	options.Transport = transport_options;
	return options;
}

static Azure::Core::Credentials::TokenCredentialOptions
ToTokenCredentialOptions(const Azure::Core::Http::Policies::TransportOptions &transport_options) {
	Azure::Core::Credentials::TokenCredentialOptions options;
	options.Transport = transport_options;
	return options;
}

static std::shared_ptr<Azure::Core::Credentials::TokenCredential>
CreateChainedTokenCredential(const std::string &chain,
                             const Azure::Core::Http::Policies::TransportOptions &transport_options) {
	auto credential_options = ToTokenCredentialOptions(transport_options);

	// Create credential chain
	auto chain_list = StringUtil::Split(chain, ';');
	Azure::Identity::ChainedTokenCredential::Sources sources;
	for (const auto &item : chain_list) {
		if (item == "cli") {
			sources.push_back(std::make_shared<Azure::Identity::AzureCliCredential>(credential_options));
		} else if (item == "managed_identity") {
			sources.push_back(std::make_shared<Azure::Identity::ManagedIdentityCredential>(credential_options));
		} else if (item == "env") {
			sources.push_back(std::make_shared<Azure::Identity::EnvironmentCredential>(credential_options));
		} else if (item == "default") {
			sources.push_back(std::make_shared<Azure::Identity::DefaultAzureCredential>(credential_options));
		} else if (item != "none") {
			throw InvalidInputException("Unknown credential provider found: " + item);
		}
	}
	return std::make_shared<Azure::Identity::ChainedTokenCredential>(sources);
}

static std::shared_ptr<Azure::Core::Credentials::TokenCredential>
CreateClientCredential(const std::string &tenant_id, const std::string &client_id, const std::string &client_secret,
                       const std::string &client_certificate_path,
                       const Azure::Core::Http::Policies::TransportOptions &transport_options) {
	auto credential_options = ToTokenCredentialOptions(transport_options);
	if (!client_secret.empty()) {
		return std::make_shared<Azure::Identity::ClientSecretCredential>(tenant_id, client_id, client_secret,
		                                                                 credential_options);
	} else if (!client_certificate_path.empty()) {
		return std::make_shared<Azure::Identity::ClientCertificateCredential>(
		    tenant_id, client_id, client_certificate_path, credential_options);
	}

	throw InvalidInputException("Failed to fetch key 'client_secret' or 'client_certificate_path' from secret "
	                            "'service_principal' of type 'azure'");
}

static Azure::Core::Http::Policies::TransportOptions GetTransportOptions(const KeyValueSecret &secret) {
	Azure::Core::Http::Policies::TransportOptions transport_options;

	auto http_proxy = secret.TryGetValue("http_proxy");
	if (!http_proxy.IsNull()) {
		transport_options.HttpProxy = http_proxy.ToString();
	} else {
		// Keep honoring the env variable if present
		auto *http_proxy_env = std::getenv("HTTP_PROXY");
		if (http_proxy_env != nullptr) {
			transport_options.HttpProxy = http_proxy_env;
		}
	}

	auto http_proxy_user_name = secret.TryGetValue("proxy_user_name");
	if (!http_proxy_user_name.IsNull()) {
		transport_options.ProxyUserName = http_proxy_user_name.ToString();
	}

	auto http_proxypassword = secret.TryGetValue("proxy_password");
	if (!http_proxypassword.IsNull()) {
		transport_options.ProxyPassword = http_proxypassword.ToString();
	}

	return transport_options;
}

static Azure::Storage::Blobs::BlobServiceClient
GetStorageAccountClientFromConfigProvider(const KeyValueSecret &secret) {
	auto transport_options = GetTransportOptions(secret);

	// If connection string, we're done heres
	auto connection_string = secret.TryGetValue("connection_string");
	if (!connection_string.IsNull()) {
		auto blob_options = ToBlobClientOptions(transport_options);
		return Azure::Storage::Blobs::BlobServiceClient::CreateFromConnectionString(connection_string.ToString(),
		                                                                            blob_options);
	}

	// Default provider (config) with no connection string => public storage account
	auto account_name = secret.TryGetValue("account_name", true);

	std::string endpoint = DEFAULT_ENDPOINT;
	auto endpoint_value = secret.TryGetValue("endpoint");
	if (!endpoint_value.IsNull()) {
		endpoint = endpoint_value.ToString();
	}

	auto account_url = "https://" + account_name.ToString() + "." + endpoint;
	auto blob_options = ToBlobClientOptions(transport_options);
	return Azure::Storage::Blobs::BlobServiceClient(account_url, blob_options);
}

static Azure::Storage::Blobs::BlobServiceClient
GetStorageAccountClientFromCredentialChainProvider(const KeyValueSecret &secret) {
	auto transport_options = GetTransportOptions(secret);
	auto account_name = secret.TryGetValue("account_name", true);

	std::string chain = "default";
	auto chain_value = secret.TryGetValue("chain");
	if (!chain_value.IsNull()) {
		chain = chain_value.ToString();
	}

	std::string endpoint = DEFAULT_ENDPOINT;
	auto endpoint_value = secret.TryGetValue("endpoint");
	if (!endpoint_value.IsNull()) {
		endpoint = endpoint_value.ToString();
	}

	// Create credential chain
	auto credential = CreateChainedTokenCredential(chain, transport_options);

	// Connect to storage account
	auto account_url = "https://" + account_name.ToString() + "." + endpoint;
	auto blob_options = ToBlobClientOptions(transport_options);
	return Azure::Storage::Blobs::BlobServiceClient(account_url, std::move(credential), blob_options);
}

static Azure::Storage::Blobs::BlobServiceClient
GetStorageAccountClientFromServicePrincipalProvider(const KeyValueSecret &secret) {
	auto transport_options = GetTransportOptions(secret);

	constexpr bool error_on_missing = true;
	auto tenant_id = secret.TryGetValue("tenant_id", error_on_missing);
	auto client_id = secret.TryGetValue("client_id", error_on_missing);
	auto client_secret_val = secret.TryGetValue("client_secret");
	auto client_certificate_path_val = secret.TryGetValue("client_certificate_path");

	std::string client_secret = client_secret_val.IsNull() ? "" : client_secret_val.ToString();
	std::string client_certificate_path =
	    client_certificate_path_val.IsNull() ? "" : client_certificate_path_val.ToString();

	auto token_credential = CreateClientCredential(tenant_id.ToString(), client_id.ToString(), client_secret,
	                                               client_certificate_path, transport_options);

	auto account_name = secret.TryGetValue("account_name", error_on_missing);

	std::string endpoint = DEFAULT_ENDPOINT;
	auto endpoint_value = secret.TryGetValue("endpoint");
	if (!endpoint_value.IsNull()) {
		endpoint = endpoint_value.ToString();
	}

	auto account_url = "https://" + account_name.ToString() + "." + endpoint;
	auto blob_options = ToBlobClientOptions(transport_options);
	return Azure::Storage::Blobs::BlobServiceClient {account_url, token_credential, blob_options};
}

static Azure::Storage::Blobs::BlobServiceClient GetStorageAccountClient(const KeyValueSecret &secret) {
	auto &provider = secret.GetProvider();
	// default provider
	if (provider == "config") {
		return GetStorageAccountClientFromConfigProvider(secret);
	} else if (provider == "credential_chain") {
		return GetStorageAccountClientFromCredentialChainProvider(secret);
	} else if (provider == "service_principal") {
		return GetStorageAccountClientFromServicePrincipalProvider(secret);
	}

	throw InvalidInputException("Unsupported provider type %s for azure", provider);
}

static Azure::Core::Http::Policies::TransportOptions GetTransportOptions(FileOpener *opener) {
	Azure::Core::Http::Policies::TransportOptions transport_options;

	// Load proxy options
	auto http_proxy = TryGetCurrentSetting(opener, "azure_http_proxy");
	if (!http_proxy.empty()) {
		transport_options.HttpProxy = http_proxy;
	}

	auto http_proxy_user_name = TryGetCurrentSetting(opener, "azure_proxy_user_name");
	if (!http_proxy_user_name.empty()) {
		transport_options.ProxyUserName = http_proxy_user_name;
	}

	auto http_proxy_password = TryGetCurrentSetting(opener, "azure_proxy_password");
	if (!http_proxy_password.empty()) {
		transport_options.ProxyPassword = http_proxy_password;
	}

	return transport_options;
}

static Azure::Storage::Blobs::BlobServiceClient GetStorageAccountClient(FileOpener *opener) {
	auto transport_options = GetTransportOptions(opener);
	auto blob_options = ToBlobClientOptions(transport_options);

	auto connection_string = TryGetCurrentSetting(opener, "azure_storage_connection_string");
	if (!connection_string.empty()) {
		return Azure::Storage::Blobs::BlobServiceClient::CreateFromConnectionString(connection_string, blob_options);
	}

	auto endpoint = TryGetCurrentSetting(opener, "azure_endpoint");
	if (endpoint.empty()) {
		endpoint = DEFAULT_ENDPOINT;
	}

	auto azure_account_name = TryGetCurrentSetting(opener, "azure_account_name");
	if (azure_account_name.empty()) {
		throw InvalidInputException("No valid Azure credentials found!");
	}

	auto account_url = "https://" + azure_account_name + "." + endpoint;
	// Credential chain secret equivalent
	auto credential_chain = TryGetCurrentSetting(opener, "azure_credential_chain");
	if (!credential_chain.empty()) {
		auto credential = CreateChainedTokenCredential(credential_chain, transport_options);

		return Azure::Storage::Blobs::BlobServiceClient(account_url, std::move(credential), blob_options);
	}

	// Anonymous
	return Azure::Storage::Blobs::BlobServiceClient {account_url, blob_options};
}

Azure::Storage::Blobs::BlobServiceClient ConnectToStorageAccount(FileOpener *opener, const std::string &path) {
	// Lookup Secret
	auto context = opener->TryGetClientContext();

	// Firstly, try to use the auth from the secret
	if (context) {
		auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*context);
		auto secret_lookup = context->db->config.secret_manager->LookupSecret(transaction, path, "azure");
		if (secret_lookup.HasMatch()) {
			const auto &base_secret = secret_lookup.GetSecret();
			return GetStorageAccountClient(dynamic_cast<const KeyValueSecret &>(base_secret));
		}
	}

	// No secret found try to connect with variables
	return GetStorageAccountClient(opener);
}

} // namespace duckdb