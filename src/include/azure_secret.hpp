#pragma once

#include "azure_extension.hpp"
#include "duckdb.hpp"
#include <duckdb/main/secret/secret.hpp>

#include <azure/identity/azure_cli_credential.hpp>
#include <azure/identity/chained_token_credential.hpp>
#include <azure/identity/default_azure_credential.hpp>
#include <azure/identity/environment_credential.hpp>
#include <azure/identity/managed_identity_credential.hpp>
#include <azure/storage/blobs.hpp>

namespace duckdb {
struct CreateSecretInput;
class CreateSecretFunction;

struct CreateAzureSecretFunctions {
public:
	//! Register all CreateSecretFunctions
	static void Register(DatabaseInstance &instance);
};

} // namespace duckdb
