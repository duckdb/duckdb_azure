#include "azure_parsed_url.hpp"
#include "azure_dfs_filesystem.hpp"
#include "duckdb/common/exception.hpp"

namespace duckdb {

AzureParsedUrl ParseUrl(const std::string &url) {
	constexpr auto invalid_url_format =
	    "The URL %s does not match the expected formats: (azure|az)://<container>/[<path>] or the fully qualified one: "
	    "(abfs[s]|azure|az)://<storage account>.<endpoint>/<container>/[<path>] "
		"or abfs[s]://<container>@<storage account>.<endpoint>/[<path>]";
	bool is_fully_qualified;
	std::string container, storage_account_name, endpoint, prefix, path;

	if (url.rfind("azure://", 0) != 0 && url.rfind("az://", 0) != 0 &&
	    url.rfind(AzureDfsStorageFileSystem::PATH_PREFIX, 0) != 0 && url.rfind(AzureDfsStorageFileSystem::UNSECURE_PATH_PREFIX, 0) != 0) {
		throw IOException("URL needs to start with azure:// or az:// or %s or %s",
			AzureDfsStorageFileSystem::PATH_PREFIX,
			AzureDfsStorageFileSystem::UNSECURE_PATH_PREFIX);
	}
	const auto prefix_end_pos = url.find("//") + 2;

	// To keep compatibility with the initial version of the extension the <storage account name>.<endpoint>/ are
	// optional nevertheless if the storage account is specify we expect the endpoint as well. Like this we hope that
	// they will be no more changes to path format.
	const auto dot_pos = url.find('.', prefix_end_pos);
	const auto slash_pos = url.find('/', prefix_end_pos);
	const auto at_pos = url.find('@', prefix_end_pos);
	if (slash_pos == std::string::npos) {
		throw duckdb::IOException(invalid_url_format, url);
	}

	if (dot_pos != std::string::npos && dot_pos < slash_pos) {
		is_fully_qualified = true;

		if ((
				url.rfind(AzureDfsStorageFileSystem::PATH_PREFIX, 0) == 0 ||
				url.rfind(AzureDfsStorageFileSystem::UNSECURE_PATH_PREFIX, 0) == 0
			) &&
			at_pos != std::string::npos) {
			// syntax is abfs[s]://<container>@<storage account>.<endpoint>/[<path>]
			const auto path_slash_pos = url.find('/', prefix_end_pos + 1);
			if (path_slash_pos == string::npos) {
				throw IOException(invalid_url_format, url);
			}			

			container = url.substr(prefix_end_pos, at_pos - prefix_end_pos);
			storage_account_name = url.substr(at_pos + 1, dot_pos - at_pos - 1);
			endpoint = url.substr(dot_pos + 1, path_slash_pos - dot_pos - 1);
			path = url.substr(path_slash_pos + 1);
		} else {
			// syntax is (abfs[s]|azure|az)://<storage account>.<endpoint>/<container>/[<path>]
			const auto container_slash_pos = url.find('/', dot_pos);
			if (container_slash_pos == string::npos) {
				throw IOException(invalid_url_format, url);
			}
			const auto path_slash_pos = url.find('/', container_slash_pos + 1);
			if (path_slash_pos == string::npos) {
				throw IOException(invalid_url_format, url);
			}
			storage_account_name = url.substr(prefix_end_pos, dot_pos - prefix_end_pos);
			endpoint = url.substr(dot_pos + 1, container_slash_pos - dot_pos - 1);
			container = url.substr(container_slash_pos + 1, path_slash_pos - container_slash_pos - 1);
			path = url.substr(path_slash_pos + 1);
		}
	} else {
		// syntax is (azure|az)://<container>/[<path>]
		// Storage account name will be retrieve from the variables or the secret information
		container = url.substr(prefix_end_pos, slash_pos - prefix_end_pos);
		if (container.empty()) {
			throw IOException(invalid_url_format, url);
		}

		is_fully_qualified = false;
		path = url.substr(slash_pos + 1);
	}
	prefix = url.substr(0, prefix_end_pos);

	return {is_fully_qualified, prefix, storage_account_name, endpoint, container, path};
}

} // namespace duckdb
