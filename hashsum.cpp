#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <array>
#include <thread>
#include <mutex>
#include <atomic>
#include <iomanip>
#include <chrono>
#include <condition_variable>

#ifdef _MSC_VER
#define  _UNUSED_
#include "getopt.h"
#else
#define  _UNUSED_  __attribute__((unused))
#include <unistd.h>
#include <limits.h>
#endif

#include "gosthash/gosthash2012.h"
#include "blake3/blake3.h"
#include "ansi_terminal.h"

#include "hashsum.h"

thread_local unsigned char tl_buff[FILE_BUF_SIZE];
thread_local std::chrono::microseconds tl_read_time = std::chrono::microseconds::zero();
thread_local std::chrono::microseconds tl_calc_time = std::chrono::microseconds::zero();


#ifdef _MSC_VER
static inline bool is_file(const char* filepath) { return true; }
#else
#include <sys/stat.h>
static inline bool is_file(const char* filepath) {
	struct stat sb;
	return stat(filepath, &sb) == 0 && S_ISREG(sb.st_mode);
}
#endif


static unsigned int thread_count = 0;
static hash_digest_impl  digest;
static unsigned short digest_size = 32;

// Blake3 (256) 
size_t blake3_digest(std::istream& istr, _UNUSED_ unsigned short _unused, unsigned char out[64]) noexcept {
	alignas(16) blake3_hasher ctx;
	//unsigned char buff[FILE_BUF_SIZE];

#ifdef STAT_FEATURE
	high_resolution_clock::time_point t1;
	high_resolution_clock::time_point t2;
#endif

	size_t length = 0;

	blake3_hasher_init(&ctx);

	do {

#ifdef STAT_FEATURE
		t1 = high_resolution_clock::now();
#endif

		istr.read((char*)tl_buff, sizeof(tl_buff));
		size_t size = static_cast <size_t> (istr.gcount());

#ifdef STAT_FEATURE
		t2 = high_resolution_clock::now();
		auto time_span = std::chrono::duration_cast <std::chrono::microseconds> (t2 - t1);
		tl_read_time += time_span;
#endif

		blake3_hasher_update(&ctx, tl_buff, size);

#ifdef STAT_FEATURE
		t1 = high_resolution_clock::now();
		time_span = std::chrono::duration_cast <std::chrono::microseconds> (t1 - t2);
		tl_calc_time += time_span;
#endif

		length += size;
	} while (!istr.eof());

#ifdef STAT_FEATURE
	t1 = high_resolution_clock::now();
#endif

	blake3_hasher_finalize(&ctx, out, 64);

#ifdef STAT_FEATURE
	t2 = high_resolution_clock::now();
	auto time_span = std::chrono::duration_cast <std::chrono::microseconds> (t2 - t1);
	tl_calc_time += time_span;
#endif

	return length;
}


/// GOST 34.11-2012 digest impl
/// digest_size = 32 for GOST 34.11-2012(256) 
/// digest_size = 64 for GOST 34.11-2012(512) 
size_t gost3411_2012_digest(std::istream& istr, unsigned short digest_size, unsigned char out[64])  noexcept {
	alignas(16) gost2012_hash_ctx ctx;
	//unsigned char buff[FILE_BUF_SIZE];

#ifdef STAT_FEATURE
	high_resolution_clock::time_point t1;
	high_resolution_clock::time_point t2;
#endif

	size_t length = 0;

	init_gost2012_hash_ctx(&ctx, int(digest_size) * 8);

	do {
#ifdef STAT_FEATURE
		t1 = high_resolution_clock::now();
#endif

		istr.read((char*)tl_buff, sizeof(tl_buff));
		size_t size = static_cast<size_t>(istr.gcount());

#ifdef STAT_FEATURE
		t2 = high_resolution_clock::now();

		auto time_span = std::chrono::duration_cast <std::chrono::microseconds> (t2 - t1);
		tl_read_time += time_span;
#endif

		gost2012_hash_block(&ctx, tl_buff, size);

#ifdef STAT_FEATURE
		t1 = high_resolution_clock::now();
		time_span = std::chrono::duration_cast <std::chrono::microseconds> (t1 - t2);
		tl_calc_time += time_span;
#endif

		length += size;
	} while (!istr.eof());

#ifdef STAT_FEATURE
	t1 = high_resolution_clock::now();
#endif

	gost2012_finish_hash(&ctx, out);

#ifdef STAT_FEATURE
	t2 = high_resolution_clock::now();
	auto time_span = std::chrono::duration_cast <std::chrono::microseconds> (t2 - t1);
	tl_calc_time += time_span;
#endif

	return length;
}


/// task slot
class alignas(16) HashLine {
	unsigned char m_digest[64];

public:
	std::string filename;
	std::atomic_ushort result;
	size_t length;

	HashLine(const HashLine&) = delete;
	HashLine(HashLine&&) = delete;
	HashLine& operator = (HashLine&& other) = delete;
	HashLine& operator = (HashLine& other) = delete;

	HashLine() {
#if __cplusplus > 201402L
		static_assert(result.is_always_lock_free);
#endif
		Release();
	}

	inline void Release() noexcept {
		result.store(static_cast<unsigned short>(HashResult::Initial), std::memory_order_release);
	}

	inline void SetHashResult(HashResult r) noexcept {
		result.store(static_cast <unsigned short> (r), std::memory_order_release);
	}

#ifndef STRICT_CONV
	static inline unsigned int _char(int c) {
		c -= 48;
		c = (c > 48) ? (c - 32) : c;
		return (c > 16) ? c - 7 : c;
	}
#else
	static inline unsigned int _char(int c) {
		if (c >= 'A') {
			if (c <= 'F') {
				return c - 'A' + 10;
			}
			else if (c >= 'a' && c <= 'f') {
				return c - 'a' + 10;
			}
		}
		else if (c >= '0' && c <= '9') {
			return c - '0';
		}
		return 0xFFFFFFFF;
	}
#endif
	/// [FIXME] buffer overflow
	bool hex2bin(const char* str, int shift) noexcept {
		unsigned int c;
		const char* pend = str + 64;
		while (str < pend) {
			c = _char(*str++) << 4;
			c += _char(*str++);
			if (c > 0xFF) {
				return false;
			}
			m_digest[shift++] = static_cast <unsigned char> (c);
		}
		return true;
	}

	inline HashResult getHashResult() const {
		return static_cast <HashResult> (result.load(std::memory_order_acquire));
	}

	static inline
		const char* result_str(HashResult r) {
		switch (r) {
		case HashResult::Initial:
			return RES_UNKNOWN_NAME;
		case HashResult::Success:
			return RES_SUCCESS_NAME;
		case HashResult::FileError:
			return RES_FILE_ERR_NAME;
		case HashResult::HashMismatch:
			return RES_HASH_MISMATCH_NAME;
		default:
			return RES_DEFAULT_NAME;
		}
	}

	static HashResult get_digest(const char* input, unsigned char actual[64], size_t& length) {

		if (input != nullptr) {
			if (!::is_file(input)) {
				return HashResult::FileError;
			}
			//if (!fs::is_regular_file(input)) {
			//	return HashResult::FileError;
			//}

			std::ifstream f(input, std::ios::binary | std::ios::in  );

			if (!f.good()) {
				length = 0;
				return HashResult::FileError;
			}
			length = ::digest(f, ::digest_size, actual);
		}
		else {
			length = ::digest(std::cin, ::digest_size, actual);
		}
		return HashResult::Success;
	}

	HashResult verifyDigest() {
		unsigned char actual[64];
		if (HashResult::Success != HashLine::get_digest(filename.empty() ? nullptr : filename.c_str(), actual, this->length)) {
			return HashResult::FileError;
		}

		if (memcmp(m_digest, actual, int(::digest_size)) == 0) {
			return HashResult::Success;
		}
		else {
			return HashResult::HashMismatch;
		}
	}

	void print_status(HashResult r) const {
		std::cerr << filename << " - ";
		std::cerr << (r == HashResult::Success ? cGREEN : cRED) << result_str(r) << cNORM << "\n";
	}

}; //use C++11 standard alignas attribute instead of GNUC specific __attribute__ ((aligned (16)));

typedef decltype(HashLine().result.load()) result_t;


/// output formated hash digest as hex string  on stdout or stderr
static inline void print_digest(std::ostream& ostr, unsigned char digest[], unsigned short digest_size) {
	ostr << std::setfill('0') << std::setw(2) << std::hex << std::right;

	for (unsigned short i = 0; i < digest_size; i++) {
		ostr << std::setw(2) << int(digest[i]);
	}
}

/// print file hash digest
static inline GS digest_file(const char* filename) {
	{
		unsigned char actual[64];
		size_t length;

		if (HashResult::Success != HashLine::get_digest(filename, actual, length)) {
			return GS::ERR_FILE;
		}

		print_digest(std::cout, actual, ::digest_size);
	}

	if (flag_verbose && filename != nullptr) {
		std::cout << " " << filename;
	}

	std::cout << std::endl;
	return GS::OK;
}
/// return true if any task has status Completed (success or error)
inline static bool _hascomplete(std::array < HashLine, HASH_LINE_SIZE >& hash) {
	for (auto& h : hash) {

		switch (h.getHashResult()) {
		case HashResult::Failed:
		case HashResult::HashMismatch:
		case HashResult::FileError:
		case HashResult::Success:
			return true;
		default:
			break;

		}
	}
	return false;
}
/// verify files hash digest
static GS check_file(const char* filename) {
	std::vector<std::thread> t; //threads
	std::array<HashLine, HASH_LINE_SIZE> hash;

	char hashbuf[64];
	//stop worker thread flag
	bool stop = false;
	GS res = GS::OK;

	std::mutex work_mutex;
	//fire than main thread submit task
	std::condition_variable work_var;
	//fire than worker thread release task
	std::condition_variable main_var;
	//number of  waiting tasks (submitted not taken)
	std::atomic_ushort inprogress{
	  0
	};
	std::ifstream file(filename);

	//calc check file size
	file.seekg(0, std::ios_base::end);
	std::streamoff size = file.tellg();
	file.seekg(0, std::ios_base::beg);
	if (!file) {
		return GS::ERR_FILE;
	}

	//worker thread function
	auto work = [&] {
#ifdef STAT_FEATURE
		std::chrono::microseconds wait_timeout{ 0 };
		unsigned long long l_total_size{ 0 };
		unsigned long wait_count{ 0 };
		unsigned long l_fail_count{ 0 };
#endif
		unsigned short c{
		  0
		};
		do {
			//find block in lock free loop
			for (auto& h : hash) {
				if (c == 0) break;
				result_t s = static_cast <result_t> (h.getHashResult());
				if (s == static_cast <result_t> (HashResult::Wait)) {

					if (h.result.compare_exchange_weak(s, static_cast <result_t> (HashResult::Taken),
						std::memory_order_acq_rel,
						std::memory_order_relaxed)) {
						c = inprogress.fetch_sub(1, std::memory_order_relaxed) - 1;

						auto hr = h.verifyDigest();
#ifdef STAT_FEATURE
						l_total_size += h.length;
#endif
						h.SetHashResult(hr);
						main_var.notify_one();
						//this_thread::yield();
					}
					else {
						//false CAS is rare case, so no need special handling 
						//c = inprogress.load( memory_order_acquire );
#ifdef STAT_FEATURE
						l_fail_count++;
#endif
					}
				}
			}

			{
				//lock and wait for notification. (work_var during wait stand in unlocked state. 
				std::unique_lock < std::mutex > lock(work_mutex);
				c = inprogress.load(std::memory_order_acquire);

				if (c == 0 && !stop) {

#ifdef STAT_FEATURE
					high_resolution_clock::time_point t1 = high_resolution_clock::now();
					wait_count++;
#endif

					work_var.wait(lock);

#ifdef STAT_FEATURE
					high_resolution_clock::time_point t2 = high_resolution_clock::now();
					wait_timeout += std::chrono::duration_cast <std::chrono::microseconds> (t2 - t1);
#endif

				}
				else if (c == 0 && stop) {
					break;
				}
			}

		} while (true); //!stop || c>0);

#ifdef STAT_FEATURE

		worker_wait_time.fetch_add(static_cast <unsigned long> (wait_timeout.count()), std::memory_order_relaxed);
		worker_wait.fetch_add(wait_count, std::memory_order_relaxed);
		total_size.fetch_add(l_total_size, std::memory_order_relaxed);
		worker_take_fail.fetch_add(l_fail_count, std::memory_order_relaxed);

		read_time.fetch_add(static_cast <unsigned long> (tl_read_time.count()), std::memory_order_relaxed);
		calc_time.fetch_add(static_cast <unsigned long> (tl_calc_time.count()), std::memory_order_relaxed);

#endif

		// end of thread worker
	};
	//check file line number
	ln = 0;
	//use single thread for small file count
	bool use_async = (size > 1000) && !flag_noasync;

	if (use_async) {

		if (thread_count == 0) {
			thread_count = std::thread::hardware_concurrency();

			if (thread_count == 0)
				thread_count = 2;
		}
		else if (thread_count > MAX_THREAD_COUNT) {
			thread_count = MAX_THREAD_COUNT;
		}

		//prepare threads pool
		for (unsigned int i = 0; i < thread_count; i++) {
			t.emplace_back(work);
		}
	}
	else {
		thread_count = 1;
	}

	//free block pointer
	HashLine* line_ptr = &hash.front();


	while (true) {
		//next line 
		ln++;
		//get first 32 byte of hash
		file.read(hashbuf, sizeof(hashbuf));
		if (file.eof() && file.gcount() == 0) {
			break;
		}
		//at least 32 byte hash must be present at the beginning of line
		if (file.gcount() != sizeof(hashbuf)) {
			res = GS::ERR_FILE;
			break;
		}
		//find free task slot
		while (line_ptr == nullptr) {

			short cc = 4; //tweak parameter
			//lock free loop
			for (auto& h : hash) {
				auto s = h.getHashResult();
				switch (s) {

				case HashResult::Failed:
					[[fallthrough]];
				case HashResult::HashMismatch:
					[[fallthrough]];
				case HashResult::FileError:
					res = GS::ERR_HASH;

					errcount++;

					[[fallthrough]];
				case HashResult::Success:
					//complete slot found
					if (flag_verbose) {
						h.print_status(s);
					}
					line_ptr = &h;
					h.Release();

					cc--;
					break;
				case HashResult::Initial:
					//free slot found
					line_ptr = &h;
					cc -= 2;

					break;
				default:
					break;
				}
				if (cc <= 0) //early exit
					break;
			}
			// not found in lock-free loop. put thread in wait notification state
			if (line_ptr == nullptr) {
				std::this_thread::yield();
				std::unique_lock < std::mutex > lock(work_mutex);

				if (!_hascomplete(hash)) {
					//increase statistics counter

#ifdef STAT_FEATURE
					main_wait++;
					high_resolution_clock::time_point t1 = high_resolution_clock::now();
#endif

					main_var.wait(lock);

#ifdef STAT_FEATURE
					high_resolution_clock::time_point t2 = high_resolution_clock::now();
					//wait time
					auto time_span = std::chrono::duration_cast <std::chrono::microseconds> (t2 - t1);
					main_wait_time += static_cast <unsigned long> (time_span.count());
#endif
				}
			}
		}
		//convert hex string to bin
		if (!line_ptr->hex2bin(hashbuf, 0)) {
			res = GS::ERR_FORMAT;
			break;
		}
		//for long hash read the rest of hash
		if (::digest_size == 64) {
			file.read(hashbuf, sizeof(hashbuf));
			if (file.gcount() != sizeof(hashbuf)) {
				res = GS::ERR_FILE;
				break;
			}

			if (!line_ptr->hex2bin(hashbuf, 32)) {
				res = GS::ERR_FORMAT;
				break;
			}
		}
		//one space is between hash hex string and file name     
		if (!file || file.get() != ' ') {
			res = GS::ERR_FILE;
			break;
		}

		//tail of the line is a file name 
		getline(file, line_ptr->filename);

		//a file name can't be empty
		if (line_ptr->filename.empty()) {
			res = GS::ERR_FILE;
			break;
		}

		if (use_async) {
			std::unique_lock < std::mutex > lock(work_mutex);
			//push task in queue
			line_ptr->SetHashResult(HashResult::Wait);
			//we use relaxed memory order because of mutex unlock sync barrier
			inprogress.fetch_add(1, std::memory_order_relaxed);
			//signal worker thread
			work_var.notify_one();
			//this_thread::yield();

			//force look for next free block
			line_ptr = nullptr;
		}
		else { //in main thread
			HashResult s = line_ptr->verifyDigest();

			if (flag_verbose) {
				line_ptr->print_status(s);
			}

#ifdef STAT_FEATURE
			//TODO read and update in main thread
			total_size.fetch_add(line_ptr->length, std::memory_order_relaxed);
#endif

			if (s != HashResult::Success) {
				res = GS::ERR_HASH;

				errcount++;

			}
			//keep line_ptr. next line can reuse it
		}
	} //end while

	{
		std::unique_lock < std::mutex > lock(work_mutex);
		stop = true;
		work_var.notify_all();
	}

	if (use_async) {
		for (auto& tt : t) {
			if (tt.joinable())
				tt.join();
		}
		//handle residual tasks
		for (auto& h : hash) {
			HashResult s = h.getHashResult();
			switch (s) {
			case HashResult::Failed:
			case HashResult::FileError:
				res = GS::ERR_FILE;
				[[fallthrough]];
			case HashResult::HashMismatch:
				res = GS::ERR_HASH;

				errcount++;

				[[fallthrough]];
			case HashResult::Success:
				if (flag_verbose) {
					h.print_status(s);
				}
				//line_ptr->result.store(RES_UNKNOWN, memory_order_release);
				break;

			case HashResult::Initial:
				break;

			default:
				res = GS::ERR_UNKNOWN;
				break;
			}
		}
	}
	return res;
}
/// brief explanation info
static int printusage(const char* executable) {

	std::cerr << "usage: " << executable << " [-h]| [-Vv][-t hashtype] filename| - | -c checkfile " << std::endl;
	std::cerr << "\thashtype - g256 - gost34.11-2012 256 bit" << std::endl;
	std::cerr << "\t         - g512 - gost34.11-2012 512 bit " << std::endl;
	std::cerr << "\t         - b3   - blake3 (fastest and default)" << std::endl;
	std::cerr << "\t -  use stdin instead of file name" << std::endl;
	std::cerr << "\t checkfile - on each line are space separated hash digest and file name" << std::endl;
	std::cerr << "\t -q quite mode. Omits filenames in the output" << std::endl;
	std::cerr << "\t -N count. Set number of threads " << std::endl;

#ifdef STAT_FEATURE
	std::cerr << "\t -s print statistics" << std::endl;
#endif

	return 0;
}

int main(int argc, char* argv[]) {
	GS rez = GS::OK;
	int f;
	const char* check_filename = nullptr;
	const char* input_filename = nullptr;
	::digest = ::blake3_digest;

	while ((f = getopt(argc, argv, "nhxsqt:vc:N:")) != -1) {
		switch (f) {
		case 'v':
			std::cout << "hashsum " << VERSION << std::endl;
			return 0;

		case 'n':
			flag_noasync = true;
			break;

		case 'q':
			flag_verbose = false;
			break;

#ifdef STAT_FEATURE
		case 's':
			flag_statistics = true;
			break;
#endif

		case 'N':
			thread_count = std::strtol(optarg, nullptr, 10);
			break;

		case 't':
			if (std::strcmp(optarg, "g256") == 0) {
				::digest = ::gost3411_2012_digest;
				::digest_size = 32;
			}
			else if (std::strcmp(optarg, "g512") == 0) {
				::digest = ::gost3411_2012_digest;
				::digest_size = 64;
			}
			else if (std::strcmp(optarg, "b3") == 0) {
				::digest = ::blake3_digest;
				::digest_size = 32;
			}
			else {
				printf("unknown -t option %s\n", optarg);
				return ::printusage(argv[0]);
			}
			break;

		case 'x':
			flag_stdin = true;
			break;

		case 'c':
			check_filename = optarg;
			break;

		case '?':
			[[fallthrough]];
		case 'h':
			std::cerr << "file hash calculation and validation tool. " << VERSION << std::endl;
			return ::printusage(argv[0]);
			break;
		};
	};

	if (check_filename) {
		::setupConsole();
		std::atexit(::restoreConsole);

#ifdef STAT_FEATURE
		high_resolution_clock::time_point t1 = high_resolution_clock::now();
#endif

		rez = check_file(check_filename);

#ifdef STAT_FEATURE
		high_resolution_clock::time_point t2 = high_resolution_clock::now();

		if (flag_statistics) {
			std::cout.precision(2);
			duration < double > time_span = duration_cast <duration < double >> (t2 - t1);

			std::cout << cBLUE "statistics"
				cNORM << std::endl;
			std::cout << std::setprecision(5);
			std::cout << " " << std::setw(20) << "read file time" << "\t: " << double(read_time) / 1000000 << " sec" << std::endl;
			std::cout << " " << std::setw(20) << "calc hash time" << "\t: " << double(calc_time) / 1000000 << " sec" << std::endl;
			std::cout << " " << std::setw(20) << "worker take fails" << "\t: " << worker_take_fail << std::endl;
			std::cout << " " << std::setw(20) << "hash fails" << "\t: " << errcount << std::endl;
			std::cout << " " << std::setw(20) << "worker wait" << "\t: " << worker_wait << std::endl;

			std::cout << " " << std::setw(20) << "worker wait time" << "\t: " << double(worker_wait_time) / 1000000 << " sec" << std::endl;
			std::cout << " " << std::setw(20) << "main wait" << "\t: " << main_wait << std::endl;
			std::cout << " " << std::setw(20) << "main wait time" << "\t: " << double(main_wait_time) / 1000000 << " sec" << std::endl;
			std::cout << " " << std::setw(20) << "elapsed time" << "\t: " << time_span.count() << " sec" << std::endl;
			std::cout << " " << std::setw(20) << "file count" << "\t: " << ln - 1 << std::endl;
			double size = double(total_size / 1024) / 1024;

			std::cout << " " << std::setw(20) << "total file size" << "\t: " << size << " Mb" << std::endl;
			std::cout << " " << std::setw(20) << "speed" << "\t: " << size / time_span.count() << " Mbps" << std::endl;
			std::cout << " " << std::setw(20) << "threads" << "\t: " << thread_count << std::endl;
		}
#endif
		if (rez != GS::OK) {
			if (flag_verbose) {
				switch (rez) {
				case GS::ERR_FORMAT:
					std::cerr << "no properly formatted hash on line " << ln << std::endl;
					break;

				case GS::ERR_FILE:
					std::cerr << "no properly formatted check file" << std::endl;
					break;

				case GS::OK:
				case GS::ERR_HASH:
					break;

				default:
					std::cerr << "error" << std::endl;
				}
				std::cerr << cRED << "check failed" << cNORM << " " << errcount << " digest errors" << std::endl;
			}
		}
		else {
			if (flag_verbose)
				std::cout << cGREEN << "OK" << cNORM << std::endl;

		}
		//restoreConsole();

	}
	else if (argv[optind] != nullptr) {

		while (argv[optind] != nullptr) {

			if (std::strcmp(argv[optind], "-") == 0) {
				//_setmode(_fileno(stdin), _O_BINARY);
				input_filename = nullptr;
			}
			else {
				input_filename = argv[optind];
			}

			::digest_file(input_filename);
			optind++;
		}
	}
	else {
		return ::printusage(argv[0]);
	}
	return static_cast<int>(rez);
}