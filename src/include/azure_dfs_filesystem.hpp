#pragma once

#include "azure_blob_filesystem.hpp"
#include <string>
namespace duckdb {

class AzureDfsStorageFileSystem : public AzureBlobStorageFileSystem {
public:
	vector<string> Glob(const string &path, FileOpener *opener = nullptr) override;

	bool CanHandleFile(const string &fpath) override;
	string GetName() const override {
		return "AzureDfsStorageFileSystem";
	}

public:
	static const string SCHEME;
	static const string PATH_PREFIX;
};

} // namespace duckdb
