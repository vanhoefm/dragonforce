add_library(util crypto.cpp crypto_ecc.cpp crypto_ffc.cpp sae.cpp)
target_link_libraries(util ssl crypto)


project(bruter)
add_executable(bruter bruter.cpp simulate.cpp)
target_link_libraries(bruter util rt)
