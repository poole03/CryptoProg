#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <stdexcept>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
using namespace CryptoPP;

int main() {
    std::string text;
    std::string result;
    
    /*
    *открытие файла и проверка
    */
    std::ifstream file("text.txt");
    if (!file.is_open()) {
        throw std::ios_base::failure("Failed to open file.");
    }
    std::string line;
    
    /*
    *чтение файла и проверка
    */
    while (std::getline(file, line))
    {
        text += line;
    }
    file.close();
    if (text.empty()) {
        throw std::ios_base::failure("File is empty.");
    }
    std::cout <<"text: " << text << std::endl;
    
    /* 
    * хэширование и вывод
    */
    Weak::MD5 hash;
    StringSource(text, true, new HashFilter(hash, new HexEncoder(new StringSink(result)))); 
    std::cout << "result: "<< result << std::endl;
    return 0; 
}
