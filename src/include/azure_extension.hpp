#pragma once

#include "duckdb.hpp"

namespace Azure {
	namespace Storage {
    	namespace Blobs {
        	class BlobClient;
        }
    }
}

namespace duckdb {

class AzureExtension : public Extension {
public:
	void Load(DuckDB &db) override;
	std::string Name() override;
};

struct AzureAuthentication {
	string connection_string;
	string container;
};

struct AzureParsedUrl {
	string container;
	string path;
};

class BlobClientWrapper {
public:
	BlobClientWrapper(AzureAuthentication auth, const string& path);
	~BlobClientWrapper();
	Azure::Storage::Blobs::BlobClient* GetClient();
protected:
	unique_ptr<Azure::Storage::Blobs::BlobClient> blob_client;
};

class AzureStorageFileHandle : public FileHandle {
public:
	AzureStorageFileHandle(FileSystem &fs, string path, uint8_t flags, AzureAuthentication auth, AzureParsedUrl parsed_url);
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
	constexpr static idx_t READ_BUFFER_LEN = 1000000;

	// Azure Blob Client
	BlobClientWrapper blob_client;
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

protected:
	static AzureParsedUrl ParseUrl(const string& url);
	void ReadRange(FileHandle &handle, idx_t file_offset, char *buffer_out, idx_t buffer_out_len);
	virtual duckdb::unique_ptr<AzureStorageFileHandle> CreateHandle(const string &path, uint8_t flags,
	                                                                FileLockType lock, FileCompressionType compression,
	                                                                FileOpener *opener);
};

} // namespace duckdb
