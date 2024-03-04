#pragma once

#include <string>

namespace duckdb {
struct AzureParsedUrl {
	const std::string container;
	const std::string storage_account_name;
	const std::string endpoint;
	const std::string prefix;
	const std::string path;
};
} // namespace duckdb
