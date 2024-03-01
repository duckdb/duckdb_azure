#pragma once

#include <string>

namespace duckdb {
struct AzureParsedUrl {
	const bool is_fully_qualified;
	const std::string prefix;
	const std::string storage_account_name;
	const std::string endpoint;
	const std::string container;
	const std::string path;
};

AzureParsedUrl ParseUrl(const std::string &url);

} // namespace duckdb
