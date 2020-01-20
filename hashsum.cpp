#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <array>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <iomanip>
#include <chrono>
#include <condition_variable>

#ifdef _MSC_VER
#include "getopt.h"
#else
#include <unistd.h>
#include <limits.h>
#endif

#include "gosthash/gosthash2012.h"
#include "blake3/blake3.h"
#include "ansi_terminal.h"

using namespace std;
using namespace std::chrono;

#define HASH_LINE_SIZE      24
#define FILE_BUF_SIZE       (1024 * 8)

enum HashResult: unsigned short {
    Initial      = 0x0000,
    Wait         = 0x0001,
    Taken        = 0x0002,
    Success      = 0xFF00,
    Failed       = 0xFFFF,
    HashMismatch = 0xFF01,
    FileError    = 0xFF02,
};

#define GS_OK               0
#define GS_ERR_HASH         1
#define GS_ERR_FILE         2
#define GS_ERR_FORMAT       3
#define GS_ERR_UNKNOWN      4

static const char* RES_UNKNOWN_NAME      ="initial";
static const char* RES_SUCCESS_NAME      ="OK";
static const char* RES_FILE_ERR_NAME     ="file error";
static const char* RES_DEFAULT_NAME      ="unknown";
static const char* RES_HASH_MISMATCH_NAME="hash mismatch";

static bool flag_verbose                = false;
static bool flag_stdin                  = false;
static bool flag_noasync                = false;
static bool flag_statistics             = false;

static unsigned long long  ln{1};
static atomic_ullong  total_size{0};

//statistics
static long          errcount{0};
static atomic_ulong  worker_take_fail{0};
static atomic_ulong  worker_wait{0}; 
static atomic_ulong  main_wait;

static atomic_ulong  worker_wait_time{0};
static atomic_ulong  main_wait_time{0};

static atomic_ulong  read_time{0};
static atomic_ulong  calc_time{0};

class HashBase{
public:
    virtual size_t  digest (istream& istr, unsigned char out[64]) const noexcept{
        return 0;
    }
    virtual unsigned short digestsize() const noexcept{
        return 0;
    }
};

class Blake3: public HashBase {
    static constexpr  unsigned short _digestsize = 32;
    unsigned short digestsize() const  noexcept{
        return _digestsize;
    }
    
    size_t  digest (istream& istr, unsigned char out[64]) const  noexcept{
        alignas(16) blake3_hasher   ctx;
        unsigned char  buff[FILE_BUF_SIZE];
        high_resolution_clock::time_point t1;
        high_resolution_clock::time_point t2;
        size_t  length = 0;
        
        blake3_hasher_init(&ctx );
        
        do{
            t1 = high_resolution_clock::now();
            
            istr.read( (char*)buff, sizeof(buff) );
            size_t size = static_cast<size_t>( istr.gcount() );
            t2 = high_resolution_clock::now(); 
            
            auto time_span = std::chrono::duration_cast< std::chrono::microseconds >(t2 - t1);
            read_time.fetch_add(  static_cast<unsigned long>( time_span.count() ), memory_order_relaxed );
                    
            
            blake3_hasher_update(&ctx, buff, size );
            t1 = high_resolution_clock::now();
            time_span = std::chrono::duration_cast< std::chrono::microseconds >(t1 - t2);
            
            calc_time.fetch_add(  static_cast<unsigned long>( time_span.count() ), memory_order_relaxed );
            
            length += size; 
        }while( !istr.eof() );
        
        t1 = high_resolution_clock::now();
        blake3_hasher_finalize(&ctx, out, 64);
        t2 = high_resolution_clock::now(); 
        auto time_span = std::chrono::duration_cast< std::chrono::microseconds >(t2 - t1);
        
        calc_time.fetch_add(  static_cast<unsigned long>( time_span.count() ), memory_order_relaxed );
        
        return length;
    }   
};

/// GOST 34.11-2012 digest impl
class Gost34112012: public HashBase {

public:
    static size_t digest(istream& istr, unsigned short digest_size, unsigned char out[64]) {
        alignas(16) gost2012_hash_ctx   ctx;
        unsigned char  buff[FILE_BUF_SIZE];
        high_resolution_clock::time_point t1;
        high_resolution_clock::time_point t2;
        size_t   length = 0;
        
        init_gost2012_hash_ctx(&ctx, int( digest_size ) * 8 );
         
        do{
            t1 = high_resolution_clock::now();
            
            istr.read( (char*)buff, sizeof(buff) );
            size_t size = static_cast<size_t>( istr.gcount() );
            t2 = high_resolution_clock::now(); 
            
            auto time_span = std::chrono::duration_cast< std::chrono::microseconds >(t2 - t1);
            read_time.fetch_add(  static_cast<unsigned long>( time_span.count() ), memory_order_relaxed );
                    
            
            gost2012_hash_block(&ctx, buff, size );
            t1 = high_resolution_clock::now();
            time_span = std::chrono::duration_cast< std::chrono::microseconds >(t1 - t2);
            
            calc_time.fetch_add(  static_cast<unsigned long>( time_span.count() ), memory_order_relaxed );
            
            length += size; 
        }while( !istr.eof() );
        
        t1 = high_resolution_clock::now();
        gost2012_finish_hash(&ctx, out);
        t2 = high_resolution_clock::now(); 
        auto time_span = std::chrono::duration_cast< std::chrono::microseconds >(t2 - t1);
        calc_time.fetch_add(  static_cast<unsigned long>( time_span.count() ), memory_order_relaxed );
        
        return length;  
    }
};

/// GOST 34.11-2012(256) digest impl
class Gost34112012_256: public Gost34112012 {
    static constexpr  unsigned short _digestsize = 32;
    unsigned short digestsize() const  noexcept{
        return _digestsize;
    }
    size_t  digest (istream& istr, unsigned char out[64]) const  noexcept{
        return Gost34112012::digest(istr, _digestsize, out);
    }
};
/// GOST 34.11-2012(512) digest impl
class Gost34112012_512: public Gost34112012 {
    static constexpr  unsigned short _digestsize = 64;
    unsigned short digestsize() const  noexcept{
        return _digestsize;
    }
    size_t  digest (istream& istr, unsigned char out[64]) const  noexcept{
        return Gost34112012::digest(istr, _digestsize, out);
    }
};
//virtual table pointers
static const Gost34112012_256 _gost34112012_256 = Gost34112012_256();
static const Gost34112012_512 _gost34112012_512 = Gost34112012_512();
static const Blake3           _blake3           = Blake3();

/// task slot
class alignas(16) HashLine{
    unsigned char       digest[64];
    
    HashResult inline _verify(){
        unsigned char actial[64];
        
        if(!filename.empty()){
            ifstream f( filename.c_str(), ios::binary | ios::in ); //open("source.pdf",);
            
            if( !f.good() ){
                return FileError;
            }
            getDigest(f, actial);
        }else{
            getDigest(cin, actial);
        }
        
        if( memcmp(digest, actial, int( hashtype->digestsize() ) ) == 0 ){
            return Success;
        }else{
            return HashMismatch;
        }
    }
    
public:
    string              filename;
    atomic_ushort       result;
    size_t              length;
    static const HashBase*  hashtype;
    
    HashLine(const HashLine&) = delete;
    HashLine(HashLine&&) = delete;
    HashLine& operator=(HashLine&& other) = delete;
    HashLine& operator=(HashLine& other) = delete;
    
    HashLine(){
#if __cplusplus > 201402L       
        static_assert( result.is_always_lock_free );
#endif
        Release();
    }
    

    inline void Release() noexcept{
        result.store(HashResult::Initial, memory_order_release);
    }
    
    inline void SetHashResult(HashResult r) noexcept{
        result.store(static_cast<unsigned short>(r), memory_order_release);
    }
    
#ifndef _STRICT_    
    static inline  unsigned int _char(int c) {
        c -= 48;
        c = (c>48)?(c-32): c;
        return (c>16)?c-7: c;
    }
#else
    static inline  unsigned int _char(int c){
        if(c>='A'){
            if(c<='F'){
                return c-'A'+10;
            }else if(c>='a' && c<='f'){
                return c-'a'+10;
            }
        }else if(c>='0' && c<='9'){
            return c-'0';
        }
        return 0xFFFFFFFF;
    }
#endif
    
    bool hex2bin(const char* str, int shift) noexcept{
        unsigned int c;
        const char* pend = str+64;
        while(str<pend){
            c  = _char(*str++) << 4;
            c += _char(*str++);
            if(c>0xFF){
                return false;
            }
            digest[shift++] = static_cast<unsigned char>(c);
        }
        return true;
    }
    
    inline HashResult getHashResult() const{
        return static_cast<HashResult>( result.load(memory_order_acquire) );
    }
    
    static inline const char * result_str(HashResult r){
        switch(r){
            case  Initial:
                return RES_UNKNOWN_NAME;
            case Success:
                return RES_SUCCESS_NAME;
            case FileError:
                return RES_FILE_ERR_NAME;
            case HashMismatch:
                return RES_HASH_MISMATCH_NAME;              
            default:
                return RES_DEFAULT_NAME;
        }
    }
    
    void getDigest(istream& istr, unsigned char out[64]) {
        length = hashtype->digest(istr, out);
    }
        
    HashResult verifyDigest(){
        auto s = _verify();
        result.store(s, memory_order_release);
        return s;
    }
    
    void print_status(HashResult r) const{
        cerr<< filename<< " - ";
        cerr<< (r == Success ? cGREEN: cRED )<< result_str(r) << cNORM<< "\n";
    }
    
}; //use C++11 standard alignas attribute instead of GNUC specific __attribute__ ((aligned (16)));


typedef   decltype( HashLine().result.load() )  result_t;
const HashBase* HashLine::hashtype = &_gost34112012_256;

/// output formated hash digest as hex string  on stdout or stderr
static inline void print_digest(ostream& ostr, unsigned char* digest, unsigned short digest_size){
    ostr<< setfill('0') << setw(2) <<hex<< right;
    
    for(unsigned short i=0; i < digest_size; i++){
        ostr << setw(2) << int(digest[i]);
    }
}

/// print file hash digest
static int digest_file(const char* filename){
    unsigned char actual[64];
    {
        HashLine  hash;
        
        if(filename!=nullptr){
            ifstream f( filename, ios::binary | ios::in ); //open("source.pdf",);
            if( !f.good() ){
                return 1;
            }
            hash.getDigest(f, actual);
        }else{
            hash.getDigest(cin, actual);
        }
        
        print_digest(cerr, actual, HashLine::hashtype->digestsize());
    }
    if(flag_verbose){
        cerr<<" "<<filename;
    }
    cerr<<endl;
    return 0;
}
/// return true if any task has status Completed (success or error)
inline static bool _hascomplete(std::array<HashLine, HASH_LINE_SIZE>&  hash){
    for(auto& h: hash){
        
        switch(h.getHashResult()){
            case Failed:
            case HashMismatch:
            case FileError:
            case Success:   
                return true;
            default:
                break;
                
        }
    }
    return false;
}
/// verify files hash digest
static int check_file(const char* filename){
    std::vector<thread> t;  //threads
    std::array<HashLine, HASH_LINE_SIZE>  hash;
    
    char hashbuf[64];
    //stop worker thread flag
    bool stop = false;
    int  res = 0;

    mutex  work_mutex;
    //fire than main thread submit task
    condition_variable work_var;
    //fire than worker thread release task
    condition_variable main_var;
    //number of  waiting tasks (submitted not taken)
    atomic_ushort   inprogress{0};
    ifstream file(filename);
    
    //calc check file size
    file.seekg(0,ios_base::end);
    std::streamoff size = file.tellg();
    file.seekg(0,ios_base::beg);
    if(!file){
        return GS_ERR_FILE;
    }
    
    //worker thread function
    auto work = [&]{     
        unsigned short c{0}; 
        do{
            //find block in lock free loop
            for(auto& h : hash){
                if(c==0) break;
                result_t s = static_cast<result_t>( h.getHashResult() ); 
                if(s == static_cast<result_t>( Wait ) ){
                    
                    if( h.result.compare_exchange_weak(s, static_cast<result_t>(Taken),
                        memory_order_release,
                        memory_order_relaxed) ) {

                        c =inprogress.fetch_sub(1, memory_order_release )-1;
                    
                        s = h.verifyDigest();
                        total_size.fetch_add(h.length, memory_order_relaxed);

                        main_var.notify_one();                      
                        //this_thread::yield();
                    }else{
                        //false CAS is rare case, so no need special handling 
                        //c = inprogress.load( memory_order_acquire );
                        worker_take_fail.fetch_add(1, memory_order_relaxed);
                    }
                }
            }
            
            {
                //lock and wait for notification. (work_var during wait stand in unlocked state. 
                unique_lock<mutex> lock(work_mutex);
                c = inprogress.load( memory_order_acquire );
          
                if(c==0 && !stop){
                    worker_wait.fetch_add(1, memory_order_relaxed);
                      
                    high_resolution_clock::time_point t1 = high_resolution_clock::now();
                    work_var.wait(lock);
                    high_resolution_clock::time_point t2 = high_resolution_clock::now();
                    
                    auto time_span = std::chrono::duration_cast< std::chrono::microseconds >(t2 - t1);
                    
                    worker_wait_time.fetch_add(  static_cast<unsigned long>( time_span.count() ), memory_order_relaxed );
                }
            }
            
        }while(!stop || c>0);
   
    };
    //check file line number
    ln = 0;
    //use single thread for small file count
    bool  use_async = (size>10000) && !flag_noasync;
    
    if(use_async){
        unsigned int thread_count = std::thread::hardware_concurrency();

        if(thread_count > 6 )
            thread_count = 6;
        if(thread_count==0)
            thread_count = 2;
        //prepare threads pool
        for(unsigned int i=0;i<thread_count;i++){
            t.emplace_back( work );
        }
    }
    
    //free block pointer
    HashLine* line_ptr = &hash.front(); 
    unsigned short digest_size = HashLine::hashtype->digestsize();
    
    while (true)
    {
        //next line 
        ln++;
        //get first 32 byte of hash
        file.read(hashbuf, sizeof(hashbuf) );
        if(file.eof() && file.gcount()==0){
            break;
        }
        //at least 32 byte hash must be present at the beginning of line
        if(file.gcount()!= sizeof(hashbuf)){
            res = GS_ERR_FILE;
            break;  
        }
        //find free task slot
        while(line_ptr == nullptr ){
               
            short cc=4; //tweak parameter
            //lock free loop
            for(auto& h: hash){
                auto s = h.getHashResult();
                switch(s){
                    
                    case Failed:
                    case HashMismatch:
                    case FileError:
                        res = GS_ERR_HASH;
                        errcount++;
                    case Success:
                        //complete slot found
                        if(flag_verbose){
                            h.print_status(s);
                        }
                        h.Release();
                        
                        line_ptr = &h;
                        cc--;
                        break;
                    case Initial:
                        //free slot found
                        line_ptr = &h;
                        cc-=2;
                   
                        break;
                    default:
                        break;
                }
                if(cc<=0) //early exit
                    break;
            }
            // not found in lock-free loop. put thread in wait notification state
            if(line_ptr==nullptr){
                this_thread::yield();
                unique_lock<mutex> lock(work_mutex);

                if(!_hascomplete(hash)){
                    //increase statistics counter
                    main_wait.fetch_add(1, memory_order_relaxed);
                    high_resolution_clock::time_point t1 = high_resolution_clock::now();
                    main_var.wait(lock);
                    high_resolution_clock::time_point t2 = high_resolution_clock::now();  
                    //wait time
                    auto time_span = std::chrono::duration_cast< std::chrono::microseconds >(t2 - t1);
                    main_wait_time.fetch_add(static_cast<unsigned long>( time_span.count() ), memory_order_relaxed );
                }       
            }
        }
        //convert hex string to bin
        if(!line_ptr->hex2bin(hashbuf, 0)){
            res = GS_ERR_FORMAT;
            break;
        }
        //for long hash read the rest of hash
        if(digest_size==64){  
            file.read(hashbuf, sizeof(hashbuf) );
            if(file.gcount()!= sizeof(hashbuf)){
                res = GS_ERR_FILE;
                break;  
            }
            
            if(!line_ptr->hex2bin(hashbuf, 32) ){
                res = GS_ERR_FORMAT;
                break;
            }           
        }
        //one space is between hash hex string and file name     
        if(!file || file.get()!=' '){
            res = GS_ERR_FILE;
            break;              
        }
            
        //tail of the line is a file name 
        getline(file, line_ptr->filename );
        
        //a file name can't be empty
        if(line_ptr->filename.empty()){
            res = GS_ERR_FILE;
            break;
        }

        if(use_async){
            unique_lock<mutex> lock(work_mutex);     
            //push task in queue
            line_ptr->SetHashResult( Wait );
            //we use relaxed memory order because of mutex unlock sync barrier
            inprogress.fetch_add(1, memory_order_relaxed);
            //signal worker thread
            work_var.notify_one();
            //this_thread::yield();
            
            //force look for next free block
            line_ptr = nullptr;
            
        }else{ //in main thread
            HashResult s = line_ptr->verifyDigest();
            
            if(flag_verbose){
                line_ptr->print_status(s);
            }
            total_size.fetch_add(line_ptr->length, memory_order_relaxed);
            
            if( s!= Success ){
                res = 1;
                errcount++;
            }            
            //keep line_ptr. next line can reuse it
        }   
    } //end while

    {
        unique_lock<mutex> lock(work_mutex);
        stop = true;
        work_var.notify_all();
    }
    
    if(use_async){
        for(auto &tt : t){         
            if(tt.joinable())
                tt.join();
        }
        //handle residual tasks
        for(auto& h: hash){
            HashResult s =  h.getHashResult(); 
            switch(s){
                case Failed:
                case FileError:
                    res = GS_ERR_FILE;
                case HashMismatch:
                    res = GS_ERR_HASH;
                    errcount++;
                case Success:
                    if(flag_verbose){
                        h.print_status(s);
                    }
                    //line_ptr->result.store(RES_UNKNOWN, memory_order_release);
                    break;
                case Initial:
                    break;
                default:
                    res = GS_ERR_UNKNOWN;
                    break;
                
            }
        }
    }
    return res;
}
/// brief explanation info
static int printusage(const char* executable){
    cerr<<"file hash calculation and validation tool"<<endl;
    cerr<<"usage: "<<executable << " [-h]| [-Vv][-t hashtype] filename| - | -c checkfile " << endl;
    cerr<<"\thashtype - g256 - gost34.11-2012 256 bit (default)" << endl;
    cerr<<"\t         - g512 - gost34.11-2012 512 bit " << endl;
    cerr<<"\t         - b3   - blake3 (fast)"<<endl;
    cerr<<"\t -  use stdin instead of file name"<<endl;
    cerr<<"\t checkfile - on each line are space separated hash digest and file name" << endl;
    cerr<<"\t -v print file name with hash on hash calculation or hash verify status on validation"<<endl;
    cerr<<"\t -V print statistics"<<endl;
    return 0;
}
    
int main(int argc, char *argv[]){
    int rez = 0;
    const char* check_filename=nullptr;
    const char* input_filename=nullptr;
    
    while ( (rez = getopt(argc,argv,"nhxt:vVc:")) != -1){
        switch (rez){
            case 'n': flag_noasync=true; break;
            case 'v': flag_verbose=true; break;
            case 'V': flag_statistics=true; break;
            case 't': 
                if( strcmp(optarg, "g256")==0 ){
                    HashLine::hashtype = &_gost34112012_256;
                }else if( strcmp(optarg, "g512")==0 ){
                    HashLine::hashtype = &_gost34112012_512;
                }else if( strcmp(optarg, "b3")==0 ){
                    HashLine::hashtype = &_blake3;
                }else{
                    printf("unknown -t option %s\n",optarg);
                    return printusage(argv[0]);
                }
                break;
            case 'x': flag_stdin=true; break;
            case 'c': check_filename = optarg; break;
            case '?': 
            case 'h': return printusage(argv[0]); break;
        };
    };
    
    
    if(check_filename){
        setupConsole();
        high_resolution_clock::time_point t1 = high_resolution_clock::now();
        rez = check_file( check_filename );
        high_resolution_clock::time_point t2 = high_resolution_clock::now();
        
        if(flag_statistics){
            cerr.precision(2);
            duration<double> time_span = duration_cast<duration<double>>(t2 - t1);
            
            cerr << cBLUE "statistics" cNORM << endl; 
            cerr << setprecision (5);
            cerr << " "<< setw(20) <<"read file time"<<"\t: "<< double(read_time)/1000000 << " sec" << endl;
            cerr << " "<< setw(20) <<"calc file time"<<"\t: "<< double(calc_time)/1000000 << " sec" << endl;
            cerr << " "<< setw(20) <<"worker take fails"<<"\t: "<< worker_take_fail << endl; 
            cerr << " "<< setw(20) <<"hash fails"<<"\t: "<< errcount << endl;
            cerr << " "<< setw(20) <<"worker wait"<<"\t: "<< worker_wait << endl;
          
            cerr << " "<< setw(20) <<"worker wait time"<<"\t: "<< double(worker_wait_time)/1000000 << " sec" << endl;
            cerr << " "<< setw(20) <<"main wait"<<"\t: "<< main_wait << endl;
            cerr << " "<< setw(20) <<"main wait time"<<"\t: "<< double(main_wait_time)/1000000 << " sec" << endl;
            cerr << " "<< setw(20) <<"elapsed time" <<"\t: "<< time_span.count() << " sec"<<endl;
            cerr << " "<< setw(20) <<"file count" <<"\t: "<< ln-1 << endl;
            double size = double(total_size / 1024)/1024;
            
            cerr << " "<< setw(20) <<"total file size" <<"\t: " << size << " Mb" << endl;
            cerr << " "<< setw(20) <<"speed" <<"\t: "<< size/time_span.count() << " Mbps"<<endl;
        }
            
        if(rez>0){
            if(flag_verbose){
                switch(rez){
                    case GS_ERR_FORMAT:
                        cerr<<"no properly formatted hash on line "<<ln << endl;
                        break;
                    case GS_ERR_FILE:
                        cerr<<"no properly formatted check file"<<endl;
                        break;
                    case GS_OK:
                    case GS_ERR_HASH:
                        break;
                    default:
                        cerr<<"error"<<endl;
                }
                cerr<< cRED << "check failed" << cNORM << " " << errcount << " digest errors" << endl;
            }               
        }else{
            if(flag_verbose)
                cerr<< cGREEN << "OK" << cNORM << endl;
            
        }
        restoreConsole();
        return rez;
    }else if (argv[optind] !=nullptr ){
        
        while(argv[optind] !=nullptr ){
        
            if( strcmp(argv[optind], "-") ==0 ){
                //flag_stdin = true;
                input_filename = nullptr;
            }else{
                input_filename = argv[optind];
            }
            rez = digest_file(input_filename);
            if( rez != GS_OK){
                break;
            }
            optind++;
        }
        
        return rez;
    }else{
        return printusage(argv[0]);
    } 
}