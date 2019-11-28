#include <iostream>

#include <tlsxx/hash/md5.hpp>

int main() {
    std::cout << tlsxx::hash::md5("").hex_digest() << std::endl;
    return 0;
}