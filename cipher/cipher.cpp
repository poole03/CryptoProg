#include <iostream>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cstring>
#include <fstream>
void encrypt(std::string keystr,const char * orig_file,const char * encr_file,const char * iv_file){
    try{
    CryptoPP::SHA256 hash;
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::PKCS12_PBKDF<CryptoPP::SHA256> pbkdf; // Создание объекта для вывода ключа из пароля с использованием алгоритма PBKDF2 с хэшем SHA-256
    pbkdf.DeriveKey(key,key.size(),0,reinterpret_cast<const CryptoPP::byte*>(keystr.data()),keystr.size(),nullptr,0,1000,0.0f); //вывод ключа из строки с использованием PBKDF2 и сохранение результата в массив key.
    CryptoPP::AutoSeededRandomPool prng; // Создание объекта для генерации случайных данных.
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    prng.GenerateBlock(iv, iv.size()); // Генерация случайных данных для инициализационного вектора
    CryptoPP::StringSource(iv, iv.size(), true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(iv_file)));                        
    std::clog << "IV generated and stored to file " << iv_file << std::endl;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encr;
    encr.SetKeyWithIV( key, key.size(), iv );
    CryptoPP::FileSource (orig_file, true,new CryptoPP::StreamTransformationFilter(encr,new CryptoPP::FileSink(encr_file)));
    std::clog << "File " << orig_file << " encrypted and stored to " << encr_file << std::endl;
    }
    catch( const CryptoPP::Exception& e ) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
}
void decrypt(std::string keystr,const char * encr_file,const char * decr_file,const char * iv_file){
    try{
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::SHA256 hash;
    CryptoPP::PKCS12_PBKDF<CryptoPP::SHA256> pbkdf;
    pbkdf.DeriveKey(key,key.size(),0,reinterpret_cast<const CryptoPP::byte*>(keystr.data()),keystr.size(),nullptr,0,1000,0.0f);
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    CryptoPP::FileSource(iv_file, true,new CryptoPP::HexDecoder(new CryptoPP::ArraySink(iv, iv.size())));
    std::clog << "IV readed from file " << iv_file << std::endl;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decr;
    decr.SetKeyWithIV(key, key.size(), iv);
    CryptoPP::FileSource (encr_file, true, new CryptoPP::StreamTransformationFilter(decr,new CryptoPP::FileSink(decr_file)));
    std::clog << "File " << encr_file << " decrypted and stored to " << decr_file << std::endl;
    }
    catch( const CryptoPP::Exception& e ) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
}
int main() {
    CryptoPP::HexEncoder(new CryptoPP::FileSink(std::cout));
    while (true){
    std::string type;
    std::cout<<"Выберите тип оперцации: en - шифрование, de - расшифрование, 0 - завершение программы"<<std::endl;
    std::cin>>type;
    if(type=="en"){
        std::string key;
        std::cout<<"Введите ключ"<<std::endl;
        std::cin>>key;

        std::string orig_file;
        std::cout<<"Введите путь к файлу для шифрования"<<std::endl;
        std::cin>>orig_file;

        std::string en_file;
        std::cout<<"Введите путь для файла с результом шифрования"<<std::endl;
        std::cin>>en_file;

        std::string iv_file;
        std::cout<<"Введите путь файла для хранения IV"<<std::endl;
        std::cin>>iv_file;

        encrypt(key,orig_file.c_str(),en_file.c_str(),iv_file.c_str());

    }
    else if(type == "de"){
        std::string key;
        std::cout<<"Введите ключ"<<std::endl;
        std::cin>>key;

        std::string enc_file;
        std::cout<<"Введите путь к файлу для расшифрования"<<std::endl;
        std::cin>>enc_file;

        std::string dec_file;
        std::cout<<"Введите путь для файла с результом расшифрования"<<std::endl;
        std::cin>>dec_file;

        std::string iv_file;
        std::cout<<"Введите путь файла для хранения IV"<<std::endl;
        std::cin>>iv_file;

        decrypt(key,enc_file.c_str(),dec_file.c_str(),iv_file.c_str());
    }
    else if(type=="0"){
        std::cout<<"Пользователь завершил работу программы"<<std::endl;
        return 0;
    }
    else{
        std::cout<<"Пользователь ввел неверный тип операции"<<std::endl;
        return 0;
        }
    }
    return 0;
}
