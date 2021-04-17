cmake_minimum_required (VERSION 3.19)

if(NOT CMAKE_BUILD_TYPE)
    if (ASAN)
        set(CMAKE_BUILD_TYPE Debug)
    else()
        set(CMAKE_BUILD_TYPE Release)
    endif()
endif()

#turn on statistics counters
add_compile_definitions(STAT_FEATURE)

if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)")
    set (X86 TRUE)
    add_compile_definitions(ENABLE_SIMD L_ENDIAN)
else ()
    set (X86 FALSE)
endif ()

set(CMAKE_C_STANDARD 11)
#target_compile_features(hashsum PRIVATE cxx_std_17)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_FLAGS_RELEASE "-O2")

set(HASHSUM_SOURCE_FILES
    hashsum.cpp
    ansi_terminal.c
 #   ansi_terminal.h
 #   getopt.h
 #   hashsum.h
)

set(BLAKE3_SOURCE_FILES
    blake3/blake3.c
    blake3/blake3_portable.c
    blake3/blake3_dispatch.c
    blake3/blake3_impl.h
    blake3/blake3.h
    blake3/blake3_sse2.c
    blake3/blake3_sse41.c
    blake3/blake3_avx2.c
    blake3/blake3_avx512.c
)

set(GOSTHASH_SOURCE_FILES
    gosthash/gosthash2012.c
    gosthash/gosthash2012.h
    gosthash/gosthash2012_const.h
    gosthash/gosthash2012_precalc.h
    gosthash/gosthash2012_ref.h
    gosthash/gosthash2012_sse2.h
)

add_executable (hashsum ${HASHSUM_SOURCE_FILES} ${GOSTHASH_SOURCE_FILES} ${BLAKE3_SOURCE_FILES})

if(MSVC)
    target_compile_options(hashsum PRIVATE /W3 /WX /MP /arch:AVX2 /wd5105)
    #SET_TARGET_PROPERTIES(hashsum PROPERTIES LINK_FLAGS "/link setargv.obj")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} setargv.obj") 
    #add_compile_options(/arch:AVX512)
    #add_compile_options(/arch:AVX2)
    #add_compile_options(/arch:SSE2) 
else() 
    target_compile_options(hashsum PRIVATE -Wall -Wextra -pedantic -Werror -march=native)
    target_link_libraries(hashsum pthread)
    
    set_source_files_properties(blake3/blake3_sse41.c PROPERTIES COMPILE_FLAGS "-msse4.1")
    set_source_files_properties(blake3/blake3_avx2.c PROPERTIES COMPILE_FLAGS "-mavx2")
    set_source_files_properties(blake3/blake3_avx512.c PROPERTIES COMPILE_FLAGS "-mavx512f -mavx512vl")

    #if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 7)
    #    target_link_libraries(hashsum stdc++fs)
    #endif()

endif()

set_target_properties(hashsum PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(TSAN)
    if (MSVC)
        message( FATAL_ERROR "Unable to run Thread Sanitizer under Windows" )
    endif()

    message(STATUS "Thread Sanitizer enabled")
    target_compile_options(hashsum PRIVATE "-fsanitize=thread;-g3")
    target_link_libraries(hashsum  "-fsanitize=thread")
endif()










