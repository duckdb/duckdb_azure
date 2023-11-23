#pragma once

#include "azure_extension.hpp"
#include "duckdb.hpp"

#include <azure/identity/azure_cli_credential.hpp>
#include <azure/identity/chained_token_credential.hpp>
#include <azure/identity/default_azure_credential.hpp>
#include <azure/identity/environment_credential.hpp>
#include <azure/identity/managed_identity_credential.hpp>
#include <azure/storage/blobs.hpp>

namespace duckdb {
struct CreateSecretInput;
class CreateSecretFunction;

// The Azure SDK doesn't appear to have a TokenCredential which is just a raw token: we need that because this
// allows our secrets to be serializable
class RawTokenCredential : public Azure::Core::Credentials::TokenCredential {
public:
	RawTokenCredential(const string& token_name) : Azure::Core::Credentials::TokenCredential(token_name) {
	}
	Azure::Core::Credentials::AccessToken GetToken(
	    Azure::Core::Credentials::TokenRequestContext const& tokenRequestContext,
	    Azure::Core::Context const& context) const override {
	    return raw_token;
	};
	Azure::Core::Credentials::AccessToken raw_token;
};

class AzureSecret : public BaseKeyValueSecret {
public:
	static case_insensitive_set_t GetRedactionSet() {
		return {"connection_string"};
	}
	AzureSecret(BaseKeyValueSecret &secret) : BaseKeyValueSecret(secret) {
		redact_keys = GetRedactionSet();
	};
	AzureSecret(BaseSecret &secret) : BaseKeyValueSecret(secret) {
		redact_keys = GetRedactionSet();
	};
	AzureSecret(vector<string> &prefix_paths_p, string &type, string &provider, string &name)
	    : BaseKeyValueSecret(prefix_paths_p, type, provider, name) {
		redact_keys = GetRedactionSet();
	};

	unique_ptr<Azure::Storage::Blobs::BlobContainerClient> GetContainerClient(AzureParsedUrl &url) const {
		if (secret_map.find("connection_string") != secret_map.end()) {
			return make_uniq<Azure::Storage::Blobs::BlobContainerClient>(
			    Azure::Storage::Blobs::BlobContainerClient::CreateFromConnectionString(secret_map.at("connection_string"), url.container));
		}

		if (secret_map.find("credential_chain") != secret_map.end()) {
			auto raw_token_credential = make_shared<RawTokenCredential>(name);
			raw_token_credential->raw_token.Token = secret_map.at("current_token");
			raw_token_credential->raw_token.ExpiresOn = Azure::DateTime::Parse(secret_map.at("expires_on"), Azure::DateTime::DateFormat::Rfc3339);

			string azure_endpoint = secret_map.at("endpoint");
			if (azure_endpoint.empty()) {
				azure_endpoint = "blob.core.windows.net";
			}

			auto accountURL = "https://" + secret_map.at("account_name") + "." + azure_endpoint;
			Azure::Storage::Blobs::BlobServiceClient blob_service_client(accountURL, raw_token_credential);
			return make_uniq<Azure::Storage::Blobs::BlobContainerClient>(blob_service_client.GetBlobContainerClient(url.container));
		}

		return nullptr;
	}

	void SetConnectionString(const string& connection_string) {
		secret_map["connection_string"] = connection_string;
	}

	void SetCredentialChainToken(const string& credential_chain, const string& account_name, const string& current_token, const string& expires_on, const string& endpoint = "") {
		secret_map["credential_chain"] = credential_chain;
		secret_map["account_name"] = account_name;
		secret_map["current_token"] = current_token;
		secret_map["expires_on"] = expires_on;
		secret_map["endpoint"] = endpoint;
	}
};

struct CreateAzureSecretFunctions {
public:
	//! Register all CreateSecretFunctions
	static void Register(DatabaseInstance &instance);
};

} // namespace duckdb
