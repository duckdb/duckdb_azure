#pragma once

#include "duckdb.hpp"

namespace Azure {
namespace Storage {
namespace Blobs {
class BlobClient;
}
} // namespace Storage
} // namespace Azure

namespace duckdb {
class HTTPState;

class AzureExtension : public Extension {
public:
	void Load(DuckDB &db) override;
	std::string Name() override;
};

struct AzureAuthentication {
	//! Auth method #1: setting the connection string
	string connection_string;

	//! Auth method #2: setting account name + defining a credential chain.
	string account_name;
	string credential_chain;
	string endpoint;
};

struct AzureReadOptions {
	int32_t transfer_concurrency = 5;
	int64_t transfer_chunk_size = 1 * 1024 * 1024;
	idx_t buffer_size = 1 * 1024 * 1024;
};

struct AzureParsedUrl {
	string container;
	string prefix;
	string path;
};

class BlobClientWrapper {
public:
	BlobClientWrapper(AzureAuthentication &auth, AzureParsedUrl &url);
	~BlobClientWrapper();
	Azure::Storage::Blobs::BlobClient *GetClient();

protected:
	unique_ptr<Azure::Storage::Blobs::BlobClient> blob_client;
};

class AzureStorageFileHandle : public FileHandle {
public:
	AzureStorageFileHandle(FileSystem &fs, string path, uint8_t flags, AzureAuthentication &auth,
	                       const AzureReadOptions &read_options, AzureParsedUrl parsed_url);
	~AzureStorageFileHandle() override = default;

public:
	void Close() override {
	}

	uint8_t flags;
	idx_t length;
	time_t last_modified;

	// Read info
	idx_t buffer_available;
	idx_t buffer_idx;
	idx_t file_offset;
	idx_t buffer_start;
	idx_t buffer_end;

	// Read buffer
	duckdb::unique_ptr<data_t[]> read_buffer;

	// Azure Blob Client
	BlobClientWrapper blob_client;

	AzureReadOptions read_options;
};

class AzureStorageFileSystem : public FileSystem {
public:
	duckdb::unique_ptr<FileHandle> OpenFile(const string &path, uint8_t flags, FileLockType lock = DEFAULT_LOCK,
	                                        FileCompressionType compression = DEFAULT_COMPRESSION,
	                                        FileOpener *opener = nullptr) final;

	vector<string> Glob(const string &path, FileOpener *opener = nullptr) override;

	// FS methods
	void Read(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) override;
	int64_t Read(FileHandle &handle, void *buffer, int64_t nr_bytes) override;
	void FileSync(FileHandle &handle) override;
	int64_t GetFileSize(FileHandle &handle) override;
	time_t GetLastModifiedTime(FileHandle &handle) override;
	bool FileExists(const string &filename) override;
	void Seek(FileHandle &handle, idx_t location) override;
	bool CanHandleFile(const string &fpath) override;
	bool CanSeek() override {
		return true;
	}
	bool OnDiskFile(FileHandle &handle) override {
		return false;
	}
	bool IsPipe(const string &filename) override {
		return false;
	}
	string GetName() const override {
		return "AzureStorageFileSystem";
	}

	static void Verify();

public:
	static mutex azure_log_lock;
	static weak_ptr<HTTPState> http_state;
	static bool listener_set;

protected:
	static AzureParsedUrl ParseUrl(const string &url);
	static void ReadRange(FileHandle &handle, idx_t file_offset, char *buffer_out, idx_t buffer_out_len);
	virtual duckdb::unique_ptr<AzureStorageFileHandle> CreateHandle(const string &path, uint8_t flags,
	                                                                FileLockType lock, FileCompressionType compression,
	                                                                FileOpener *opener);
};

} // namespace duckdb
