SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
set(checker_sources
  checker.cpp)

set(checker_headers)

set(checker_private_headers
  checker.h)

monero_private_headers(checker
  ${checker_private_headers})
monero_add_executable(checker
  ${checker_sources}
  ${checker_headers}
  ${checker_private_headers})
target_link_libraries(checker
  PRIVATE
    blockchain_db
    cryptonote_basic
    cryptonote_core
    cncrypto
    common
    ${EPEE_READLINE}
    version
    ${Boost_CHRONO_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_LOCALE_LIBRARY}
    ${ICU_LIBRARIES}
    ${Boost_THREAD_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${GNU_READLINE_LIBRARY}
    ${EXTRA_LIBRARIES})
set_property(TARGET checker
  PROPERTY
    OUTPUT_NAME "checker")
install(TARGETS checker DESTINATION bin)
