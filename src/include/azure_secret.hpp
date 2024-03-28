#pragma once

#include "duckdb/main/database.hpp"

namespace duckdb {
struct CreateAzureSecretFunctions {
public:
	//! Register all CreateSecretFunctions
	static void Register(DatabaseInstance &instance);
};

} // namespace duckdb
