#include <string>
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

using namespace std;

#ifndef TIMESTAMPLIBRARY_H
#define TIMESTAMPLIBRARY_H


// Funzione per convertire una stringa di timestamp in un oggetto std::tm
tm parseTimestamp(string& timestamp) {
    tm tm = {};
    stringstream ss(timestamp);
    ss >> get_time(&tm, "%Y-%m-%d %H:%M:%S");
    if (ss.fail()) {
        throw runtime_error("Parsing failed");
    }
    return tm;
}


int secondDifference(string timestamp1 , string timestamp2){
    // The second is the bigger one
    try {
        // Convertire i timestamp in oggetti std::tm
        tm tm1 = parseTimestamp(timestamp1);
        tm tm2 = parseTimestamp(timestamp2);

        // Convertire gli oggetti tm in chrono::system_clock::time_point
        auto tp1 = chrono::system_clock::from_time_t(mktime(&tm1));
        auto tp2 = chrono::system_clock::from_time_t(mktime(&tm2));

        // Calcolare la differenza tra i due time_point
        return (static_cast<int>(chrono::duration_cast<chrono::seconds>(tp2 - tp1).count()));
    } catch (const exception& e) {
        return -1;
    }
}

std::string getCurrentTimestamp() {
    // Ottieni il tempo corrente in millisecondi
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);

    // Ottieni il tempo da epoch in millisecondi
    auto since_epoch = ms.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(since_epoch);
    auto fractional_seconds = std::chrono::duration_cast<std::chrono::milliseconds>(since_epoch) % 1000;

    // Ottieni il tempo da epoch in secondi
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);

    // Formatta il timestamp in una stringa
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&currentTime), "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << fractional_seconds.count();

    return oss.str();
}

bool checkTimestampFormat(string timestamp){
    return true;
}

#endif