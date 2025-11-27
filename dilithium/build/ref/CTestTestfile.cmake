# CMake generated Testfile for 
# Source directory: /home/zhan4630/pq_fl_project/dilithium/ref
# Build directory: /home/zhan4630/pq_fl_project/dilithium/build/ref
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(dilithium2_ref "/home/zhan4630/pq_fl_project/dilithium/build/ref/test_dilithium2_ref")
set_tests_properties(dilithium2_ref PROPERTIES  _BACKTRACE_TRIPLES "/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;72;add_test;/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;0;")
add_test(dilithium2aes_ref "/home/zhan4630/pq_fl_project/dilithium/build/ref/test_dilithium2aes_ref")
set_tests_properties(dilithium2aes_ref PROPERTIES  _BACKTRACE_TRIPLES "/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;73;add_test;/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;0;")
add_test(dilithium3_ref "/home/zhan4630/pq_fl_project/dilithium/build/ref/test_dilithium3_ref")
set_tests_properties(dilithium3_ref PROPERTIES  _BACKTRACE_TRIPLES "/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;74;add_test;/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;0;")
add_test(dilithium3aes_ref "/home/zhan4630/pq_fl_project/dilithium/build/ref/test_dilithium3aes_ref")
set_tests_properties(dilithium3aes_ref PROPERTIES  _BACKTRACE_TRIPLES "/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;75;add_test;/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;0;")
add_test(dilithium5_ref "/home/zhan4630/pq_fl_project/dilithium/build/ref/test_dilithium5_ref")
set_tests_properties(dilithium5_ref PROPERTIES  _BACKTRACE_TRIPLES "/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;76;add_test;/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;0;")
add_test(dilithium5aes_ref "/home/zhan4630/pq_fl_project/dilithium/build/ref/test_dilithium5aes_ref")
set_tests_properties(dilithium5aes_ref PROPERTIES  _BACKTRACE_TRIPLES "/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;77;add_test;/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;0;")
add_test(vectors2_ref "sh" "-c" "\"/home/zhan4630/pq_fl_project/dilithium/build/ref/test_vectors2_ref\" > tvecs2")
set_tests_properties(vectors2_ref PROPERTIES  _BACKTRACE_TRIPLES "/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;87;add_test;/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;0;")
add_test(vectors2aes_ref "sh" "-c" "\"/home/zhan4630/pq_fl_project/dilithium/build/ref/test_vectors2aes_ref\" > tvecs2aes")
set_tests_properties(vectors2aes_ref PROPERTIES  _BACKTRACE_TRIPLES "/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;88;add_test;/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;0;")
add_test(vectors3_ref "sh" "-c" "\"/home/zhan4630/pq_fl_project/dilithium/build/ref/test_vectors3_ref\" > tvecs3")
set_tests_properties(vectors3_ref PROPERTIES  _BACKTRACE_TRIPLES "/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;89;add_test;/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;0;")
add_test(vectors3aes_ref "sh" "-c" "\"/home/zhan4630/pq_fl_project/dilithium/build/ref/test_vectors3aes_ref\" > tvecs3aes")
set_tests_properties(vectors3aes_ref PROPERTIES  _BACKTRACE_TRIPLES "/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;90;add_test;/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;0;")
add_test(vectors5_ref "sh" "-c" "\"/home/zhan4630/pq_fl_project/dilithium/build/ref/test_vectors5_ref\" > tvecs5")
set_tests_properties(vectors5_ref PROPERTIES  _BACKTRACE_TRIPLES "/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;91;add_test;/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;0;")
add_test(vectors5aes_ref "sh" "-c" "\"/home/zhan4630/pq_fl_project/dilithium/build/ref/test_vectors5aes_ref\" > tvecs5aes")
set_tests_properties(vectors5aes_ref PROPERTIES  _BACKTRACE_TRIPLES "/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;92;add_test;/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;0;")
add_test(hashes "sha256sum" "-c" "../../SHA256SUMS")
set_tests_properties(hashes PROPERTIES  _BACKTRACE_TRIPLES "/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;95;add_test;/home/zhan4630/pq_fl_project/dilithium/ref/CMakeLists.txt;0;")
