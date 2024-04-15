#include "azure_filesystem.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/main/client_context.hpp"
#include <azure/storage/common/storage_exception.hpp>

namespace duckdb {

AzureContextState::AzureContextState(const AzureReadOptions &read_options)
    : read_options(read_options), is_valid(true) {
}

bool AzureContextState::IsValid() const {
	return is_valid;
}

void AzureContextState::QueryEnd() {
	is_valid = false;
}

AzureFileHandle::AzureFileHandle(AzureStorageFileSystem &fs, string path, FileOpenFlags flags,
                                 const AzureReadOptions &read_options)
    : FileHandle(fs, std::move(path)), flags(flags),
      // File info
      length(0), last_modified(0),
      // Read info
      buffer_available(0), buffer_idx(0), file_offset(0), buffer_start(0), buffer_end(0),
      // Options
      read_options(read_options) {
	if (flags.OpenForReading()) {
		read_buffer = duckdb::unique_ptr<data_t[]>(new data_t[read_options.buffer_size]);
	}
}

void AzureFileHandle::PostConstruct() {
	static_cast<AzureStorageFileSystem &>(file_system).LoadFileInfo(*this);
}

void AzureStorageFileSystem::LoadFileInfo(AzureFileHandle &handle) {
	if (handle.flags.OpenForReading()) {
		try {
			LoadRemoteFileInfo(handle);
		} catch (const Azure::Storage::StorageException &e) {
			throw IOException(
			    "AzureBlobStorageFileSystem open file '%s' failed with code'%s', Reason Phrase: '%s', Message: '%s'",
			    handle.path, e.ErrorCode, e.ReasonPhrase, e.Message);
		} catch (const std::exception &e) {
			throw IOException(
			    "AzureBlobStorageFileSystem could not open file: '%s', unknown error occurred, this could mean "
			    "the credentials used were wrong. Original error message: '%s' ",
			    handle.path, e.what());
		}
	}
}

unique_ptr<FileHandle> AzureStorageFileSystem::OpenFile(const string &path,FileOpenFlags flags,
														optional_ptr<FileOpener> opener) {
	D_ASSERT(flags.Compression() == FileCompressionType::UNCOMPRESSED);

	if (flags.OpenForWriting()) {
		throw NotImplementedException("Writing to Azure containers is currently not supported");
	}

	auto handle = CreateHandle(path, flags, opener);
	return std::move(handle);
}

int64_t AzureStorageFileSystem::GetFileSize(FileHandle &handle) {
	auto &afh = handle.Cast<AzureFileHandle>();
	return afh.length;
}

time_t AzureStorageFileSystem::GetLastModifiedTime(FileHandle &handle) {
	auto &afh = handle.Cast<AzureFileHandle>();
	return afh.last_modified;
}

void AzureStorageFileSystem::Seek(FileHandle &handle, idx_t location) {
	auto &sfh = handle.Cast<AzureFileHandle>();
	sfh.file_offset = location;
}

void AzureStorageFileSystem::FileSync(FileHandle &handle) {
	throw NotImplementedException("FileSync for Azure Storage files not implemented");
}

// TODO: this code is identical to HTTPFS, look into unifying it
void AzureStorageFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	auto &hfh = handle.Cast<AzureFileHandle>();

	idx_t to_read = nr_bytes;
	idx_t buffer_offset = 0;

	// Don't buffer when DirectIO is set.
	if (hfh.flags.DirectIO() && to_read > 0) {
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
			auto new_buffer_available = MinValue<idx_t>(hfh.read_options.buffer_size, hfh.length - hfh.file_offset);

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

int64_t AzureStorageFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes) {
	auto &hfh = handle.Cast<AzureFileHandle>();
	idx_t max_read = hfh.length - hfh.file_offset;
	nr_bytes = MinValue<idx_t>(max_read, nr_bytes);
	Read(handle, buffer, nr_bytes, hfh.file_offset);
	return nr_bytes;
}

std::shared_ptr<AzureContextState> AzureStorageFileSystem::GetOrCreateStorageContext(optional_ptr<FileOpener> opener,
                                                                                     const string &path,
                                                                                     const AzureParsedUrl &parsed_url) {
	Value value;
	bool azure_context_caching = true;
	if (FileOpener::TryGetCurrentSetting(opener, "azure_context_caching", value)) {
		azure_context_caching = value.GetValue<bool>();
	}

	std::shared_ptr<AzureContextState> result;
	if (azure_context_caching) {
		auto client_context = FileOpener::TryGetClientContext(opener);

		auto context_key = GetContextPrefix() + parsed_url.storage_account_name;

		auto &registered_state = client_context->registered_state;
		auto storage_account_it = registered_state.find(context_key);
		if (storage_account_it == registered_state.end()) {
			result = CreateStorageContext(opener, path, parsed_url);
			registered_state.insert(std::make_pair(context_key, result));
		} else {
			auto *azure_context_state = static_cast<AzureContextState *>(storage_account_it->second.get());
			// We keep the context valid until the QueryEnd (cf: AzureBlobContextState#QueryEnd())
			// we do so because between queries the user can change the secret/variable that has been set
			// the side effect of that is that we will reconnect (potentially retrieve a new token) on each request
			if (!azure_context_state->IsValid()) {
				result = CreateStorageContext(opener, path, parsed_url);
				registered_state[context_key] = result;
			} else {
				result = std::shared_ptr<AzureContextState>(storage_account_it->second, azure_context_state);
			}
		}
	} else {
		result = CreateStorageContext(opener, path, parsed_url);
	}

	return result;
}

AzureReadOptions AzureStorageFileSystem::ParseAzureReadOptions(optional_ptr<FileOpener> opener) {
	AzureReadOptions options;

	Value concurrency_val;
	if (FileOpener::TryGetCurrentSetting(opener, "azure_read_transfer_concurrency", concurrency_val)) {
		options.transfer_concurrency = concurrency_val.GetValue<int32_t>();
	}

	Value chunk_size_val;
	if (FileOpener::TryGetCurrentSetting(opener, "azure_read_transfer_chunk_size", chunk_size_val)) {
		options.transfer_chunk_size = chunk_size_val.GetValue<int64_t>();
	}

	Value buffer_size_val;
	if (FileOpener::TryGetCurrentSetting(opener, "azure_read_buffer_size", buffer_size_val)) {
		options.buffer_size = buffer_size_val.GetValue<idx_t>();
	}

	return options;
}

time_t AzureStorageFileSystem::ToTimeT(const Azure::DateTime &dt) {
	auto time_point = static_cast<std::chrono::system_clock::time_point>(dt);
	return std::chrono::system_clock::to_time_t(time_point);
}

} // namespace duckdb
