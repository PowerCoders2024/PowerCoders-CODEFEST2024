set(CMAKE_CXX_STANDARD 20)
target_link_libraries(a.out ${GTEST_LIBRARIES})
# Directorios para los archivos fuente de la biblioteca
include_directories(${CMAKE_SOURCE_DIR}/../../)  # Ruta a los encabezados de la biblioteca
link_directories(${CMAKE_SOURCE_DIR}/../../lib)  # Ruta a las bibliotecas (si es necesario)

add_library(DateConverter_lib
        ../../CipherSuite.cpp
        ../../SpaceServer/Satellite.cpp
        ../../EarthClient/EarthBase.cpp
        ../../CryptoUser/CryptoUser.cpp
)
add_executable(Google_Tests_run
        SuiteTests.cpp ProveTest.cpp
)
target_link_libraries(Google_Tests_run
        DateConverter_lib
        gtest
        wolfssl
        pthread
)
include(GoogleTest)
gtest_discover_tests(Google_Tests_run)
enable_testing()
add_test(add a.out)
