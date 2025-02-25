#include <string>
#include <vector>
#include <iostream>
#include <limits>
#include <regex>

using namespace std;

#ifndef UTILITY_H
#define UTILITY_H

bool checkEmailFormat(string emailRecv){
    regex emailRegex(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)"); //regular expression for the email format
    return regex_match(emailRecv, emailRegex);  //check the received string with the regex
}

std::vector<std::string> divideString(string str, char delimiter = '-') {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string item;
    
    while (std::getline(ss, item, delimiter)) {
        result.push_back(item);
    }

    return result;
}


void substituteWhiteSpaces(string& input, bool to_from){
    const unsigned int size = input.length();
    for(unsigned int i = 0 ; i < size ; i++){
        if(input.at(i) == ' ' && to_from == false){
            input.at(i) = '_';
        } else if(input.at(i) == '_' && to_from == true){
            input.at(i) = ' ';
        }
    }
}

string insertLineFromKeyboard(){
    std::string body;
    std::getline(std::cin, body);
    return body;
}

unsigned int countOccurrencies(string input, char c){
    const unsigned int size = input.length();
    unsigned int count = 0;
    for(unsigned int i = 0 ; i < size ; i++){
        if(input.at(i) == c){
            count++;
        }
    }
    return count;
}

std::string toHex(const std::vector<unsigned char>& data) {
    std::string hexStr;
    for (unsigned char byte : data) {
        char buf[3];
        sprintf(buf, "%02x", byte);
        hexStr.append(buf);
    }
    return hexStr;
}

std::string toHex(const std::string& data) {
    std::string hexStr;
    for (unsigned char byte : data) {
        char buf[3];
        sprintf(buf, "%02x", byte);
        hexStr.append(buf);
    }
    return hexStr;
}

// Funzione per convertire std::vector<unsigned char> in std::string
std::string vectorUnsignedCharToString(const std::vector<unsigned char>& vec) {
    return std::string(vec.begin(), vec.end());
}

// Funzione per convertire std::string in std::vector<unsigned char>
std::vector<unsigned char> stringToVectorUnsignedChar(const std::string& str) {
    return std::vector<unsigned char>(str.begin(), str.end());
}

bool containsNumbers(string str) {
    for(char c : str) {
        if(!isdigit(c)) {
            return false;
        }
    }
    return true;
}



#endif