#include "azure_dfs_filesystem.hpp"
#include "azure_storage_account_client.hpp"
#include "duckdb/function/scalar/string_functions.hpp"
#include <algorithm>
#include <azure/storage/files/datalake/datalake_file_system_client.hpp>
#include <azure/storage/files/datalake/datalake_directory_client.hpp>
#include <azure/storage/files/datalake/datalake_options.hpp>
#include <azure/storage/files/datalake/datalake_responses.hpp>
#include <cstddef>
#include <string>
#include <vector>

namespace duckdb {
const string AzureDfsStorageFileSystem::SCHEME = "abfss";
const string AzureDfsStorageFileSystem::PATH_PREFIX = "abfss://";

inline static bool IsDfsScheme(const string &fpath) {
	return fpath.rfind("abfss://", 0) == 0;
}

static void Walk(const Azure::Storage::Files::DataLake::DataLakeFileSystemClient &fs, const std::string &path,
                 const string &path_pattern, std::size_t end_match, std::vector<std::string> *out_result) {
	constexpr bool recursive = false;
	auto directory_client = fs.GetDirectoryClient(path);

	Azure::Storage::Files::DataLake::ListPathsOptions options;
	while (true) {
		auto res = directory_client.ListPaths(recursive, options);

		for (const auto &elt : res.Paths) {
			if (elt.IsDirectory) {
				if (LikeFun::Glob(elt.Name.data(), elt.Name.length(), path_pattern.data(), end_match)) {
					if (end_match >= path_pattern.length()) {
						// Skip, no way there will be matches anymore
						continue;
					}
					Walk(fs, elt.Name, path_pattern,
					     std::min(path_pattern.length(), path_pattern.find('/', end_match + 1)), out_result);
				}
			} else {
				// File
				if (LikeFun::Glob(elt.Name.data(), elt.Name.length(), path_pattern.data(), path_pattern.length())) {
					out_result->push_back(elt.Name);
				}
			}
		}

		if (res.NextPageToken) {
			options.ContinuationToken = res.NextPageToken;
		} else {
			break;
		}
	}
}

bool AzureDfsStorageFileSystem::CanHandleFile(const string &fpath) {
	return IsDfsScheme(fpath);
}

vector<string> AzureDfsStorageFileSystem::Glob(const string &path, FileOpener *opener) {
	if (opener == nullptr) {
		throw InternalException("Cannot do Azure storage Glob without FileOpener");
	}

	auto azure_url = ParseUrl(path);

	// If path does not contains any wildcard, we assume that an absolute path therefor nothing to do
	auto first_wildcard_pos = azure_url.path.find_first_of("*[\\");
	if (first_wildcard_pos == string::npos) {
		return {path};
	}

	// The path contains wildcard try to list file with the minimum calls
	auto dfs_storage_service = ConnectToDfsStorageAccount(opener, path, azure_url);
	auto dfs_filesystem_client = dfs_storage_service.GetFileSystemClient(azure_url.container);

	auto index_root_dir = azure_url.path.rfind('/', first_wildcard_pos);
	if (index_root_dir == string::npos) {
		index_root_dir = 0;
	}
	auto shared_path = azure_url.path.substr(0, index_root_dir);

	std::vector<std::string> result;
	Walk(dfs_filesystem_client, shared_path,
	     // pattern to match
	     azure_url.path, std::min(azure_url.path.length(), azure_url.path.find('/', index_root_dir + 1)),
	     // output result
	     &result);

	if (!result.empty()) {
		const auto path_result_prefix =
		    (azure_url.is_fully_qualified ? (azure_url.prefix + azure_url.storage_account_name + '.' +
		                                     azure_url.endpoint + '/' + azure_url.container)
		                                  : (azure_url.prefix + azure_url.container)) +
		    '/';
		for (auto &elt : result) {
			elt = path_result_prefix + elt;
		}
	}

	return result;
}
} // namespace duckdb
