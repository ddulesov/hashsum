// hashsum.h : включаемый файл для стандартных системных включаемых файлов
// или включаемые файлы для конкретного проекта.

#pragma once
#include <functional>
//

typedef std::function<size_t(std::istream& istr, unsigned short digest_size,  unsigned char out[64])> hash_digest_impl;

static const std::size_t HASH_LINE_SIZE = 24;
static const std::size_t FILE_BUF_SIZE = (1024 * 8);
static const     int MAX_THREAD_COUNT = 8;

enum class HashResult : unsigned short {
	Initial,
	Wait,
	Taken,
	Success,
	Failed,
	HashMismatch,
	FileError,
};

enum class GS : int {
	OK = 0,
	ERR_HASH = 1,
	ERR_FILE = 2,
	ERR_FORMAT = 3,
	ERR_UNKNOWN = 4
};
//#define GS_OK 0
//#define GS_ERR_HASH 1
//#define GS_ERR_FILE 2
//#define GS_ERR_FORMAT 3
//#define GS_ERR_UNKNOWN 4

static
const char* VERSION = "0.1.1";

static
const char* RES_UNKNOWN_NAME = "initial";
static
const char* RES_SUCCESS_NAME = "OK";
static
const char* RES_FILE_ERR_NAME = "file error";
static
const char* RES_DEFAULT_NAME = "unknown";
static
const char* RES_HASH_MISMATCH_NAME = "hash mismatch";

static bool flag_verbose = true;
static bool flag_stdin = false;
static bool flag_noasync = false;


static long errcount{
  0
};
static unsigned long long ln{
  1
};

#ifdef STAT_FEATURE
using namespace std::chrono;

static bool flag_statistics = false;
static std::atomic_ullong total_size{
  0
};

//statistics

static std::atomic_ulong worker_take_fail{
  0
};
static std::atomic_ulong worker_wait{
  0
};
static unsigned long main_wait;

static std::atomic_ulong worker_wait_time{
  0
};
static unsigned long main_wait_time{
  0
};

static std::atomic_ulong read_time{
  0
};
static std::atomic_ulong calc_time{
  0
};

#endif