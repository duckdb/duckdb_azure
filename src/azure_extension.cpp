#define DUCKDB_EXTENSION_MAIN

#include "azure_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/common/file_opener.hpp"

#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

#include <iostream>

#include <azure/storage/blobs.hpp>

namespace duckdb {

BlobClientWrapper::BlobClientWrapper(AzureAuthentication auth, const string& path) {
	auto container_client = Azure::Storage::Blobs::BlobContainerClient::CreateFromConnectionString(auth.connection_string, auth.container);
	container_client.CreateIfNotExists();
	blob_client = make_uniq<Azure::Storage::Blobs::BlockBlobClient>(container_client.GetBlockBlobClient(path));
}
BlobClientWrapper::~BlobClientWrapper() = default;
Azure::Storage::Blobs::BlobClient* BlobClientWrapper::GetClient() {
    return blob_client.get();
};

unique_ptr<AzureStorageFileHandle> AzureStorageFileSystem::CreateHandle(const string &path, uint8_t flags, FileLockType lock,
                                                        FileCompressionType compression, FileOpener *opener) {
    D_ASSERT(compression == FileCompressionType::UNCOMPRESSED);
	auto parsed_url = ParseUrl(path);

	string connection_string;
	Value value;
	if (FileOpener::TryGetCurrentSetting(opener, "azure_storage_connection_string", value)) {
		connection_string = value.ToString();
	}

	if (connection_string == "") {
		throw IOException("No azure_storage_connection_string found, please set using SET azure_storage_connection_string='<your connection string>' ");
	}

	AzureAuthentication auth{
	    connection_string,
	    parsed_url.container
	};

    return make_uniq<AzureStorageFileHandle>(*this, path, flags, auth, parsed_url);
}

unique_ptr<FileHandle> AzureStorageFileSystem::OpenFile(const string &path, uint8_t flags, FileLockType lock,
                                                FileCompressionType compression, FileOpener *opener) {
    D_ASSERT(compression == FileCompressionType::UNCOMPRESSED);
    auto handle = CreateHandle(path, flags, lock, compression, opener);
    return std::move(handle);
}

AzureStorageFileHandle::AzureStorageFileHandle(FileSystem &fs, string path_p, uint8_t flags, AzureAuthentication auth, AzureParsedUrl parsed_url)
    : FileHandle(fs, std::move(path_p)), flags(flags), length(0), buffer_available(0), buffer_idx(0), file_offset(0),
      buffer_start(0), buffer_end(0), blob_client(std::move(auth), parsed_url.path) {
	try {
		auto client = *blob_client.GetClient();
		auto res = client.GetProperties();
		length = res.Value.BlobSize;
	} catch (Azure::Storage::StorageException &e) {
		throw IOException("AzureStorageFileSystem open file " + path + " failed with " + e.ErrorCode + "Reason Phrase: " + e.ReasonPhrase);
	}

	if (flags & FileFlags::FILE_FLAGS_READ) {
		read_buffer = duckdb::unique_ptr<data_t[]>(new data_t[READ_BUFFER_LEN]);
	}
}

int64_t AzureStorageFileSystem::GetFileSize(FileHandle &handle) {
    auto &afh = (AzureStorageFileHandle &)handle;
    return afh.length;
}

time_t AzureStorageFileSystem::GetLastModifiedTime(FileHandle &handle) {
    auto &afh = (AzureStorageFileHandle &)handle;
    return afh.last_modified;
}

// TODO: this is currently a bit weird: it should be az:// but that shit dont work
bool AzureStorageFileSystem::CanHandleFile(const string &fpath) {
    return fpath.rfind("azure://", 0) == 0;
}

void AzureStorageFileSystem::Seek(FileHandle &handle, idx_t location) {
    auto &sfh = (AzureStorageFileHandle &)handle;
    sfh.file_offset = location;
}

void AzureStorageFileSystem::FileSync(FileHandle &handle) {
    throw NotImplementedException("FileSync for Azure Storage files not implemented");
}

static void LoadInternal(DatabaseInstance &instance) {
    auto &fs = instance.GetFileSystem();
    fs.RegisterSubSystem(make_uniq<AzureStorageFileSystem>());

	auto &config = DBConfig::GetConfig(instance);
	config.AddExtensionOption("azure_storage_connection_string", "Azure connection string, used for authenticating and configuring azure requests", LogicalType::VARCHAR);
}

int64_t AzureStorageFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes) {
    auto &hfh = (AzureStorageFileHandle &)handle;
    idx_t max_read = hfh.length - hfh.file_offset;
    nr_bytes = MinValue<idx_t>(max_read, nr_bytes);
    Read(handle, buffer, nr_bytes, hfh.file_offset);
    return nr_bytes;
}

// TODO: this code is identical to HTTPFS, look into unifying it
void AzureStorageFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	auto &hfh = (AzureStorageFileHandle &)handle;

	idx_t to_read = nr_bytes;
	idx_t buffer_offset = 0;

	// Don't buffer when DirectIO is set.
	if (hfh.flags & FileFlags::FILE_FLAGS_DIRECT_IO && to_read > 0) {
		ReadRange(hfh, location, (char *)buffer, to_read);
		hfh.buffer_available = 0;
		hfh.buffer_idx = 0;
		hfh.file_offset = location + nr_bytes;
		return;
	}

	if (location >= hfh.buffer_start && location < hfh.buffer_end) {
		hfh.file_offset = location;
		hfh.buffer_idx = location - hfh.buffer_start;
		hfh.buffer_available = (hfh.buffer_end - hfh.buffer_start) - hfh.buffer_idx;
	} else {
		// reset buffer
		hfh.buffer_available = 0;
		hfh.buffer_idx = 0;
		hfh.file_offset = location;
	}
	while (to_read > 0) {
		auto buffer_read_len = MinValue<idx_t>(hfh.buffer_available, to_read);
		if (buffer_read_len > 0) {
			D_ASSERT(hfh.buffer_start + hfh.buffer_idx + buffer_read_len <= hfh.buffer_end);
			memcpy((char *)buffer + buffer_offset, hfh.read_buffer.get() + hfh.buffer_idx, buffer_read_len);

			buffer_offset += buffer_read_len;
			to_read -= buffer_read_len;

			hfh.buffer_idx += buffer_read_len;
			hfh.buffer_available -= buffer_read_len;
			hfh.file_offset += buffer_read_len;
		}

		if (to_read > 0 && hfh.buffer_available == 0) {
			auto new_buffer_available = MinValue<idx_t>(hfh.READ_BUFFER_LEN, hfh.length - hfh.file_offset);

			// Bypass buffer if we read more than buffer size
			if (to_read > new_buffer_available) {
				ReadRange(hfh, location + buffer_offset, (char *)buffer + buffer_offset, to_read);
				hfh.buffer_available = 0;
				hfh.buffer_idx = 0;
				hfh.file_offset += to_read;
				break;
			} else {
				ReadRange(hfh, hfh.file_offset, (char *)hfh.read_buffer.get(), new_buffer_available);
				hfh.buffer_available = new_buffer_available;
				hfh.buffer_idx = 0;
				hfh.buffer_start = hfh.file_offset;
				hfh.buffer_end = hfh.buffer_start + new_buffer_available;
			}
		}
	}
}

bool AzureStorageFileSystem::FileExists(const string &filename) {
	try {
		auto handle = OpenFile(filename, FileFlags::FILE_FLAGS_READ);
		auto &sfh = (AzureStorageFileHandle &)*handle;
		if (sfh.length == 0) {
			return false;
		}
		return true;
	} catch (...) {
		return false;
	};
}

void AzureStorageFileSystem::ReadRange(FileHandle &handle, idx_t file_offset, char *buffer_out, idx_t buffer_out_len) {
	auto &afh = (AzureStorageFileHandle &)handle;

	try {
		auto blob_client = *afh.blob_client.GetClient();

		// Specify the range
		Azure::Core::Http::HttpRange range;
		range.Offset = (int64_t)file_offset;
		range.Length = buffer_out_len;
		Azure::Storage::Blobs::DownloadBlobToOptions options;
		options.Range = range;
		auto res = blob_client.DownloadTo((uint8_t *)buffer_out, buffer_out_len, options);

	} catch (Azure::Storage::StorageException &e) {
		throw IOException("AzureStorageFileSystem Read to " + afh.path + " failed with " + e.ErrorCode + "Reason Phrase: " + e.ReasonPhrase);
	}
}

AzureParsedUrl AzureStorageFileSystem::ParseUrl(const string& url) {
	string container, path;

	if (url.rfind("azure://", 0) != 0) {
		throw IOException("URL needs to start with s3://");
	}
	auto slash_pos = url.find('/', 8);
	if (slash_pos == string::npos) {
		throw IOException("URL needs to contain a '/' after the host");
	}
	container = url.substr(8, slash_pos - 8);
	if (container.empty()) {
		throw IOException("URL needs to contain a bucket name");
	}

	path = url.substr(slash_pos+1);
	return {container, path};
}

void AzureExtension::Load(DuckDB &db) {
	LoadInternal(*db.instance);
}
std::string AzureExtension::Name() {
	return "azure";
}

} // namespace duckdb

extern "C" {

DUCKDB_EXTENSION_API void azure_init(duckdb::DatabaseInstance &db) {
	LoadInternal(db);
}

DUCKDB_EXTENSION_API const char *azure_version() {
	return duckdb::DuckDB::LibraryVersion();
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
