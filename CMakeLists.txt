set(CMAKE_CXX_FLAGS "-O3")

add_library(util crypto.cpp crypto_ecc.cpp crypto_ffc.cpp sae.cpp)
target_link_libraries(util ssl crypto)

project(bruter)
add_executable(bruter bruter.cpp simulate.cpp passwordlist.cpp timingresults.cpp)
target_link_libraries(bruter util rt)

project(brainpool)
add_executable(brainpool brainpool.cpp hostap_sae.cpp)
target_link_libraries(brainpool util rt)
