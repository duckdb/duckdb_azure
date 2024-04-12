#pragma once

#include "duckdb/main/database.hpp"

namespace duckdb {

void RegisterAzureDeviceCodeFunction(DatabaseInstance &instance);

} // namespace duckdb
