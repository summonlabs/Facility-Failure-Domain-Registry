// Facility Failure Domain Registry - DCCP boundary 49.
//
// Durable store implementation. The authoritative state is one file containing
//   header | canonical payload | SHA-256 trailer
// published by staged write, flush, read-back verification and atomic replace.
// Mutation authority is a kernel-owned exclusive lock on a sibling epoch record
// file, so it is released by process death rather than by cooperation.
#include "storage.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "canonical.hpp"
#include "checked.hpp"
#include "ffd/testing/crash_injection.hpp"
#include "sha256.hpp"
#include "validate.hpp"

namespace ffd::detail {
namespace {

constexpr char kStoreMagic[8] = {'F', 'F', 'D', 'R', 'G', 'E', 'N', '1'};
constexpr char kLockMagic[8] = {'F', 'F', 'D', 'R', 'L', 'C', 'K', '1'};

[[nodiscard]] std::string win32_message(DWORD code) {
  LPWSTR buffer = nullptr;
  const DWORD length = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&buffer),
      0, nullptr);
  std::string message;
  if (length != 0 && buffer != nullptr) {
    const std::wstring wide(buffer, length);
    for (const wchar_t character : wide) {
      if (character == L'\r' || character == L'\n') {
        continue;
      }
      message.push_back(character < 0x80 ? static_cast<char>(character) : '?');
    }
    LocalFree(buffer);
  }
  if (message.empty()) {
    message = "Win32 error " + std::to_string(code);
  }
  return message;
}

[[nodiscard]] Error io_error(std::string what, DWORD code) {
  return Error{ErrorCode::StorageIo, std::move(what) + ": " + win32_message(code)};
}

struct Win32Handle {
  HANDLE value{INVALID_HANDLE_VALUE};

  Win32Handle() = default;
  explicit Win32Handle(HANDLE handle) noexcept : value(handle) {}
  Win32Handle(const Win32Handle&) = delete;
  Win32Handle& operator=(const Win32Handle&) = delete;
  Win32Handle(Win32Handle&& other) noexcept : value(other.value) {
    other.value = INVALID_HANDLE_VALUE;
  }
  Win32Handle& operator=(Win32Handle&& other) noexcept {
    if (this != &other) {
      close();
      value = other.value;
      other.value = INVALID_HANDLE_VALUE;
    }
    return *this;
  }
  ~Win32Handle() { close(); }

  void close() noexcept {
    if (value != INVALID_HANDLE_VALUE && value != nullptr) {
      CloseHandle(value);
    }
    value = INVALID_HANDLE_VALUE;
  }
  [[nodiscard]] bool valid() const noexcept {
    return value != INVALID_HANDLE_VALUE && value != nullptr;
  }
  void reset(HANDLE handle) noexcept {
    close();
    value = handle;
  }
};

// Every Win32 call goes through an extended-length path. That both supports
// stores nested more deeply than MAX_PATH and keeps device names such as CON or
// NUL as ordinary file names, so a hostile store name cannot reach a device.
[[nodiscard]] std::filesystem::path extended_path(const std::filesystem::path& path) {
  std::error_code ec;
  std::filesystem::path absolute = std::filesystem::absolute(path, ec);
  if (ec) {
    absolute = path;
  }
  absolute = absolute.lexically_normal();
  const std::wstring native = absolute.native();
  if (native.rfind(L"\\\\?\\", 0) == 0) {
    return absolute;
  }
  if (!absolute.has_root_directory()) {
    return absolute;
  }
  if (native.rfind(L"\\\\", 0) == 0) {
    return std::filesystem::path(std::wstring(L"\\\\?\\UNC\\") + native.substr(2));
  }
  return std::filesystem::path(std::wstring(L"\\\\?\\") + native);
}

[[nodiscard]] Status write_all(HANDLE handle, const std::uint8_t* data, std::size_t size,
                               ffd::testing::CrashPoint crash_point) {
  std::size_t written = 0;
  bool crashed = false;
  while (written < size) {
    const std::size_t remaining = size - written;
    const DWORD chunk = static_cast<DWORD>(remaining > 65536 ? 65536 : remaining);
    DWORD produced = 0;
    if (WriteFile(handle, data + written, chunk, &produced, nullptr) == FALSE) {
      return io_error("staged write failed", GetLastError());
    }
    if (produced == 0) {
      return Error{ErrorCode::StorageIo, "staged write made no progress"};
    }
    written += produced;
    if (!crashed && written * 2 >= size && size > 1) {
      crashed = true;
      ffd::testing::reach_crash_point(crash_point);
    }
  }
  return Status{};
}

[[nodiscard]] Result<std::vector<std::uint8_t>> read_whole_file(const std::filesystem::path& path,
                                                                std::uint64_t max_bytes) {
  const std::filesystem::path native = extended_path(path);
  Win32Handle handle(CreateFileW(native.c_str(), GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!handle.valid()) {
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      return Error{ErrorCode::NotFound, "store file does not exist"};
    }
    return io_error("open for read failed", error);
  }
  LARGE_INTEGER size{};
  if (GetFileSizeEx(handle.value, &size) == FALSE) {
    return io_error("query file size failed", GetLastError());
  }
  if (size.QuadPart < 0) {
    return Error{ErrorCode::CorruptState, "file size is negative"};
  }
  const auto unsigned_size = static_cast<std::uint64_t>(size.QuadPart);
  if (unsigned_size > max_bytes) {
    return Error{ErrorCode::LimitExceeded,
                 "store file exceeds the configured maximum payload size"};
  }
  std::vector<std::uint8_t> bytes(static_cast<std::size_t>(unsigned_size));
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const std::size_t remaining = bytes.size() - offset;
    const DWORD chunk = static_cast<DWORD>(remaining > 1u << 20 ? 1u << 20 : remaining);
    DWORD produced = 0;
    if (ReadFile(handle.value, bytes.data() + offset, chunk, &produced, nullptr) == FALSE) {
      return io_error("read failed", GetLastError());
    }
    if (produced == 0) {
      return Error{ErrorCode::TruncatedState, "file ended before its declared length"};
    }
    offset += produced;
  }
  return bytes;
}

void append_bytes(std::vector<std::uint8_t>& out, const void* data, std::size_t size) {
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  out.insert(out.end(), bytes, bytes + size);
}

[[nodiscard]] std::vector<std::uint8_t> build_store_file(const ModelState& state,
                                                         std::uint64_t generation,
                                                         std::uint64_t epoch,
                                                         const Digest& model_digest,
                                                         std::size_t payload_size) {
  std::vector<std::uint8_t> out;
  out.reserve(static_cast<std::size_t>(kStoreHeaderBytes) + payload_size +
              static_cast<std::size_t>(kStoreTrailerBytes));
  append_bytes(out, kStoreMagic, sizeof(kStoreMagic));
  ByteWriter header;
  header.u32(kFormatVersion);
  header.u32(static_cast<std::uint32_t>(kStoreHeaderBytes));
  header.u64(generation);
  header.u64(epoch);
  header.u64(static_cast<std::uint64_t>(payload_size));
  header.digest(model_digest);
  append_bytes(out, header.bytes().data(), header.size());
  const std::vector<std::uint8_t> payload = encode_durable_state(state);
  append_bytes(out, payload.data(), payload.size());
  const Digest trailer = sha256(out.data(), out.size());
  append_bytes(out, trailer.bytes.data(), trailer.bytes.size());
  return out;
}

[[nodiscard]] Result<DurableSection> parse_store_file(const std::vector<std::uint8_t>& bytes,
                                                      const Limits& limits) {
  if (bytes.size() < static_cast<std::size_t>(kStoreHeaderBytes + kStoreTrailerBytes)) {
    return Error{ErrorCode::TruncatedState, "store file is shorter than its header and trailer"};
  }
  if (std::memcmp(bytes.data(), kStoreMagic, sizeof(kStoreMagic)) != 0) {
    return Error{ErrorCode::CorruptState, "store file magic does not match"};
  }
  ByteReader header(bytes.data() + sizeof(kStoreMagic), static_cast<std::size_t>(kStoreHeaderBytes) - sizeof(kStoreMagic));
  std::uint32_t format_version = 0;
  std::uint32_t header_bytes = 0;
  std::uint64_t generation = 0;
  std::uint64_t epoch = 0;
  std::uint64_t payload_length = 0;
  Digest claimed_digest;
  if (!header.u32(format_version) || !header.u32(header_bytes) || !header.u64(generation) ||
      !header.u64(epoch) || !header.u64(payload_length) || !header.digest(claimed_digest)) {
    return Error{ErrorCode::TruncatedState, "store header is truncated"};
  }
  if (format_version != kFormatVersion) {
    return Error{ErrorCode::UnsupportedFormatVersion,
                 "store format version " + std::to_string(format_version) +
                     " is not supported by this build"};
  }
  if (header_bytes != kStoreHeaderBytes) {
    return Error{ErrorCode::CorruptState, "store header length is inconsistent"};
  }
  if (payload_length > limits.max_payload_bytes) {
    return Error{ErrorCode::LimitExceeded, "declared payload exceeds the configured limit"};
  }
  const std::uint64_t expected_size =
      kStoreHeaderBytes + payload_length + kStoreTrailerBytes;
  if (static_cast<std::uint64_t>(bytes.size()) != expected_size) {
    return Error{ErrorCode::TruncatedState,
                 "store file length does not match its declared payload length"};
  }
  const std::size_t signed_size = static_cast<std::size_t>(kStoreHeaderBytes + payload_length);
  const Digest computed_trailer =
      sha256(bytes.data(), static_cast<std::size_t>(signed_size));
  if (std::memcmp(computed_trailer.bytes.data(), bytes.data() + signed_size,
                  kDigestBytes) != 0) {
    return Error{ErrorCode::DigestMismatch, "store file trailer digest does not match"};
  }

  DurableSection section;
  const Status decode_status = decode_durable_state(bytes.data() + kStoreHeaderBytes,
                                                     static_cast<std::size_t>(payload_length),
                                                     limits, section.state);
  if (!decode_status.ok()) {
    return decode_status.error();
  }
  section.generation = generation;
  section.writer_epoch = epoch;
  section.model_digest = claimed_digest;
  section.state.generation = generation;
  const Digest recomputed = digest_of(encode_model_content(section.state));
  if (!(recomputed == claimed_digest)) {
    return Error{ErrorCode::DigestMismatch,
                 "store header digest does not match the decoded model content"};
  }
  return section;
}

struct LockRecord {
  std::uint64_t epoch{0};
  std::uint64_t last_generation{0};
};

[[nodiscard]] std::vector<std::uint8_t> build_lock_record(const LockRecord& record) {
  std::vector<std::uint8_t> out;
  append_bytes(out, kLockMagic, sizeof(kLockMagic));
  ByteWriter body;
  body.u32(kFormatVersion);
  body.u32(static_cast<std::uint32_t>(kLockRecordBytes));
  body.u64(record.epoch);
  body.u64(record.last_generation);
  append_bytes(out, body.bytes().data(), body.size());
  const Digest trailer = sha256(out.data(), out.size());
  append_bytes(out, trailer.bytes.data(), trailer.bytes.size());
  return out;
}

[[nodiscard]] Result<LockRecord> parse_lock_record(const std::vector<std::uint8_t>& bytes) {
  if (bytes.empty()) {
    return LockRecord{};
  }
  if (bytes.size() != kLockRecordBytes) {
    return Error{ErrorCode::CorruptState, "epoch record length is inconsistent"};
  }
  if (std::memcmp(bytes.data(), kLockMagic, sizeof(kLockMagic)) != 0) {
    return Error{ErrorCode::CorruptState, "epoch record magic does not match"};
  }
  ByteReader reader(bytes.data() + sizeof(kLockMagic),
                    static_cast<std::size_t>(kLockRecordBytes) - sizeof(kLockMagic) - kDigestBytes);
  std::uint32_t format_version = 0;
  std::uint32_t record_bytes = 0;
  LockRecord record;
  if (!reader.u32(format_version) || !reader.u32(record_bytes) || !reader.u64(record.epoch) ||
      !reader.u64(record.last_generation)) {
    return Error{ErrorCode::CorruptState, "epoch record is truncated"};
  }
  if (format_version != kFormatVersion || record_bytes != kLockRecordBytes) {
    return Error{ErrorCode::CorruptState, "epoch record header is inconsistent"};
  }
  const Digest computed =
      sha256(bytes.data(), static_cast<std::size_t>(kLockRecordBytes - kDigestBytes));
  if (std::memcmp(computed.bytes.data(),
                  bytes.data() + (kLockRecordBytes - kDigestBytes), kDigestBytes) != 0) {
    return Error{ErrorCode::CorruptState, "epoch record digest does not match"};
  }
  return record;
}

// The epoch record lives in its own file: the kernel lock is taken on a
// separate, empty lock file, so a live writer never blocks an operator or a
// test from reading the epoch record.
// The epoch record is published with the same discipline as the store file:
// staged, flushed, read back and atomically replaced. A torn epoch record would
// otherwise make an intact store unopenable after a crash.
[[nodiscard]] Status write_epoch_record(const std::filesystem::path& epoch_path,
                                       const LockRecord& record,
                                       std::uint64_t& temp_counter) {
  const std::vector<std::uint8_t> bytes = build_lock_record(record);
  const std::filesystem::path temp_path = extended_path(std::filesystem::path(
      epoch_path.native() + L".tmp-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
      std::to_wstring(temp_counter++)));
  {
    Win32Handle handle(CreateFileW(temp_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
    if (!handle.valid()) {
      return io_error("create staged epoch record failed", GetLastError());
    }
    const Status write_status =
        write_all(handle.value, bytes.data(), bytes.size(), ffd::testing::CrashPoint::None);
    if (!write_status.ok()) {
      return write_status;
    }
    if (FlushFileBuffers(handle.value) == FALSE) {
      return io_error("flush staged epoch record failed", GetLastError());
    }
  }
  Result<std::vector<std::uint8_t>> staged = read_whole_file(temp_path, 4096);
  if (!staged.ok()) {
    return staged.error();
  }
  if (!(staged.value() == bytes)) {
    return Error{ErrorCode::StorageIo,
                 "staged epoch record read-back does not match what was written"};
  }
  if (MoveFileExW(temp_path.c_str(), extended_path(epoch_path).c_str(),
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
    return io_error("atomic epoch record publish failed", GetLastError());
  }
  return Status{};
}

[[nodiscard]] Result<std::vector<std::uint8_t>> read_epoch_bytes(
    const std::filesystem::path& epoch_path) {
  std::error_code ec;
  if (!std::filesystem::exists(extended_path(epoch_path), ec) || ec) {
    return std::vector<std::uint8_t>{};
  }
  return read_whole_file(epoch_path, 4096);
}

void remove_stale_temp_files(const std::filesystem::path& store_path) {
  std::error_code ec;
  const std::filesystem::path parent = store_path.parent_path();
  const std::wstring prefix = store_path.filename().native() + L".tmp-";
  const std::wstring epoch_prefix = store_path.filename().native() + L".epoch.tmp-";
  const std::filesystem::path directory = parent.empty() ? std::filesystem::path(L".")
                                                         : extended_path(parent);
  std::filesystem::directory_iterator iterator(directory, ec);
  if (ec) {
    return;
  }
  const std::filesystem::directory_iterator end;
  for (; iterator != end; iterator.increment(ec)) {
    if (ec) {
      return;
    }
    const std::wstring name = iterator->path().filename().native();
    const bool staged_store =
        name.size() > prefix.size() && name.compare(0, prefix.size(), prefix) == 0;
    const bool staged_epoch =
        name.size() > epoch_prefix.size() && name.compare(0, epoch_prefix.size(), epoch_prefix) == 0;
    if (staged_store || staged_epoch) {
      std::error_code remove_ec;
      std::filesystem::remove(iterator->path(), remove_ec);
    }
  }
}

}  // namespace

std::filesystem::path lock_path_for(const std::filesystem::path& store_path) {
  std::filesystem::path lock = store_path;
  lock += L".lock";
  return lock;
}

std::filesystem::path epoch_path_for(const std::filesystem::path& store_path) {
  std::filesystem::path epoch = store_path;
  epoch += L".epoch";
  return epoch;
}

// ---------------------------------------------------------------------------
// StoreFile
// ---------------------------------------------------------------------------
StoreFile::~StoreFile() {
  if (lock_handle_ != nullptr) {
    auto* handle = static_cast<HANDLE*>(lock_handle_);
    UnlockFile(*handle, 0, 0, 1, 0);
    CloseHandle(*handle);
    delete handle;
    lock_handle_ = nullptr;
  }
}

Result<std::unique_ptr<StoreFile>> StoreFile::open_writer(const StoreConfig& config,
                                                          StoreInfo& info,
                                                          DurableSection& section) {
  if (config.path.empty() || config.path.filename().empty()) {
    return Error{ErrorCode::InvalidArgument, "store path must name a file"};
  }
  const Status limits_status = validate_limits(config.limits);
  if (!limits_status.ok()) {
    return limits_status.error();
  }

  std::error_code ec;
  const std::filesystem::path parent = config.path.parent_path();
  if (!parent.empty()) {
    std::filesystem::create_directories(extended_path(parent), ec);
    if (ec && !std::filesystem::exists(extended_path(parent))) {
      return Error{ErrorCode::StorageIo, "cannot create the store directory: " + ec.message()};
    }
  }

  auto store = std::unique_ptr<StoreFile>(new StoreFile());
  store->path_ = config.path;

  const std::filesystem::path lock_path = extended_path(lock_path_for(config.path));
  auto* lock_handle = new Win32Handle(CreateFileW(
      lock_path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
      OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!lock_handle->valid()) {
    const DWORD error = GetLastError();
    delete lock_handle;
    return io_error("open epoch record failed", error);
  }

  // The lock file is a pure kernel-lock artifact: its content is irrelevant, so
  // no reader can ever be blocked by the locked byte range.
  OVERLAPPED overlapped{};
  if (LockFileEx(lock_handle->value, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0,
                 &overlapped) == FALSE) {
    const DWORD error = GetLastError();
    delete lock_handle;
    if (error == ERROR_LOCK_VIOLATION || error == ERROR_IO_PENDING) {
      return Error{ErrorCode::WriterLockUnavailable,
                   "another live process owns mutation authority for this store"};
    }
    return io_error("acquire writer lock failed", error);
  }

  store->lock_handle_ = lock_handle;

  const std::filesystem::path epoch_path = epoch_path_for(config.path);
  Result<std::vector<std::uint8_t>> epoch_bytes = read_epoch_bytes(epoch_path);
  if (!epoch_bytes.ok()) {
    return epoch_bytes.error();
  }
  Result<LockRecord> lock_record = parse_lock_record(epoch_bytes.value());
  if (!lock_record.ok()) {
    return lock_record.error();
  }

  const std::optional<std::uint64_t> next_epoch = checked_add(lock_record.value().epoch, 1ull);
  if (!next_epoch.has_value()) {
    return Error{ErrorCode::Overflow, "writer epoch is exhausted"};
  }
  if (next_epoch.value() < config.writer_epoch_floor) {
    return Error{ErrorCode::Fenced,
                 "durable writer epoch is below the configured floor; this incarnation must not "
                 "resume mutation authority"};
  }

  section = DurableSection{};
  bool existed = false;
  {
    std::error_code exists_ec;
    existed = std::filesystem::exists(extended_path(config.path), exists_ec) && !exists_ec;
  }
  if (existed) {
    const std::uint64_t max_file_bytes = config.limits.max_payload_bytes + 4096;
    Result<std::vector<std::uint8_t>> bytes = read_whole_file(config.path, max_file_bytes);
    if (!bytes.ok()) {
      return bytes.error();
    }
    Result<DurableSection> parsed = parse_store_file(bytes.value(), config.limits);
    if (!parsed.ok()) {
      return parsed.error();
    }
    section = std::move(parsed.value());
  } else if (lock_record.value().last_generation > 0) {
    return Error{ErrorCode::RollbackDetected,
                 "the durable epoch record is ahead of the store file, which is missing"};
  } else {
    section.generation = 0;
    section.writer_epoch = 0;
    section.model_digest = digest_of(encode_model_content(section.state));
  }

  if (section.writer_epoch > lock_record.value().epoch) {
    return Error{ErrorCode::RollbackDetected,
                 "the published generation was written by a later incarnation than the durable "
                 "epoch record admits"};
  }
  if (section.generation < lock_record.value().last_generation) {
    return Error{ErrorCode::RollbackDetected,
                 "the store file generation is behind the durable epoch record"};
  }

  LockRecord next_record;
  next_record.epoch = next_epoch.value();
  next_record.last_generation = section.generation;
  std::uint64_t temp_counter = 0;
  const Status write_status = write_epoch_record(epoch_path, next_record, temp_counter);
  if (!write_status.ok()) {
    return write_status.error();
  }

  store->epoch_ = next_epoch.value();
  store->durable_generation_ = section.generation;
  store->limits_ = config.limits;

  remove_stale_temp_files(config.path);

  info.store_existed = existed;
  info.writer_epoch = next_epoch.value();
  info.durable_generation = section.generation;
  info.lockfile_last_generation = lock_record.value().last_generation;
  info.durable_digest = section.model_digest;
  return store;
}

Result<DurableSection> StoreFile::read_file(const std::filesystem::path& path,
                                            const Limits& limits) {
  if (path.empty() || path.filename().empty()) {
    return Error{ErrorCode::InvalidArgument, "store path must name a file"};
  }
  const Status limits_status = validate_limits(limits);
  if (!limits_status.ok()) {
    return limits_status.error();
  }
  Result<std::vector<std::uint8_t>> bytes = read_whole_file(path, limits.max_payload_bytes + 4096);
  if (!bytes.ok()) {
    return bytes.error();
  }
  return parse_store_file(bytes.value(), limits);
}

Status StoreFile::publish(const ModelState& state, std::uint64_t generation,
                          const Digest& model_digest) {
  if (lock_handle_ == nullptr) {
    return Error{ErrorCode::ReadOnly, "store is not open for writing"};
  }
  const std::filesystem::path epoch_path = epoch_path_for(path_);
  Result<std::vector<std::uint8_t>> current = read_epoch_bytes(epoch_path);
  if (!current.ok()) {
    return current.error();
  }
  Result<LockRecord> record = parse_lock_record(current.value());
  if (!record.ok()) {
    return record.error();
  }
  if (record.value().epoch != epoch_) {
    return Error{ErrorCode::Fenced,
                 "the durable writer epoch has moved to " +
                     std::to_string(record.value().epoch) +
                     "; this incarnation may no longer publish"};
  }

  const std::vector<std::uint8_t> payload = encode_durable_state(state);
  if (static_cast<std::uint64_t>(payload.size()) > limits_.max_payload_bytes) {
    return Error{ErrorCode::LimitExceeded, "payload exceeds the configured limit"};
  }
  const std::vector<std::uint8_t> file_bytes =
      build_store_file(state, generation, epoch_, model_digest, payload.size());

  const std::filesystem::path temp_path =
      extended_path(std::filesystem::path(path_.native() + L".tmp-" +
                                          std::to_wstring(GetCurrentProcessId()) + L"-" +
                                          std::to_wstring(temp_counter_++)));
  {
    Win32Handle temp(CreateFileW(temp_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
    if (!temp.valid()) {
      return io_error("create staged file failed", GetLastError());
    }
    const Status write_status = write_all(temp.value, file_bytes.data(), file_bytes.size(),
                                          ffd::testing::CrashPoint::DuringTempWrite);
    if (!write_status.ok()) {
      return write_status;
    }
    if (FlushFileBuffers(temp.value) == FALSE) {
      return io_error("flush staged file failed", GetLastError());
    }
  }

  ffd::testing::reach_crash_point(ffd::testing::CrashPoint::AfterTempWrite);

  // Read back the staged bytes and verify them before publishing: a truncated or
  // corrupted staged file must never replace a good generation.
  Result<std::vector<std::uint8_t>> staged = read_whole_file(temp_path, 1ull << 40);
  if (!staged.ok()) {
    return staged.error();
  }
  if (!(staged.value() == file_bytes)) {
    return Error{ErrorCode::StorageIo, "staged file read-back does not match what was written"};
  }

  if (MoveFileExW(temp_path.c_str(), extended_path(path_).c_str(),
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
    return io_error("atomic publish failed", GetLastError());
  }

  ffd::testing::reach_crash_point(ffd::testing::CrashPoint::AfterPublishBeforeEpoch);

  LockRecord next_record;
  next_record.epoch = epoch_;
  next_record.last_generation = generation;
  const Status record_status = write_epoch_record(epoch_path, next_record, temp_counter_);
  if (!record_status.ok()) {
    return record_status;
  }

  ffd::testing::reach_crash_point(ffd::testing::CrashPoint::AfterPublish);

  durable_generation_ = generation;
  return Status{};
}

std::uint64_t epoch_high_water(const std::filesystem::path& store_path, bool* consistent) {
  if (consistent != nullptr) {
    *consistent = false;
  }
  const std::filesystem::path lock_path = extended_path(lock_path_for(store_path));
  Win32Handle handle(CreateFileW(lock_path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!handle.valid()) {
    return 0;
  }
  OVERLAPPED overlapped{};
  // A shared lock succeeds only when no writer holds the exclusive lock, which
  // is what makes the epoch record a consistent read.
  if (LockFileEx(handle.value, LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped) == FALSE) {
    return 0;
  }
  Result<std::vector<std::uint8_t>> bytes = read_epoch_bytes(epoch_path_for(store_path));
  std::uint64_t high_water = 0;
  if (bytes.ok()) {
    Result<LockRecord> record = parse_lock_record(bytes.value());
    if (record.ok()) {
      high_water = record.value().last_generation;
      if (consistent != nullptr) {
        *consistent = true;
      }
    }
  }
  UnlockFile(handle.value, 0, 0, 1, 0);
  return high_water;
}

}  // namespace ffd::detail

// ---------------------------------------------------------------------------
// Crash injection (test support; inert unless built with injection enabled)
// ---------------------------------------------------------------------------
namespace ffd::testing {
namespace {
std::atomic<CrashPoint> g_crash_point{CrashPoint::None};
}  // namespace

void set_crash_point(CrashPoint point) noexcept { g_crash_point.store(point); }

CrashPoint crash_point() noexcept { return g_crash_point.load(); }

bool crash_injection_enabled() noexcept {
#ifdef FFD_ENABLE_CRASH_INJECTION
  return true;
#else
  return false;
#endif
}

void reach_crash_point(CrashPoint point) noexcept {
#ifdef FFD_ENABLE_CRASH_INJECTION
  // None is the "no injection" sentinel and must never terminate a process.
  if (point != CrashPoint::None && g_crash_point.load() == point) {
    // Silent, deterministic termination: no dialog, no dump, no unwinding.
    TerminateProcess(GetCurrentProcess(), 3);
    // Not reached unless termination is intercepted by the host.
    ExitProcess(3);
  }
#else
  (void)point;
#endif
}

}  // namespace ffd::testing
