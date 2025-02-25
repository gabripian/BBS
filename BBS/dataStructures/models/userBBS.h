#include <string>
#include <vector>
#include <sstream>
using namespace std;

#ifndef USERBBS_H
#define USERBBS_H

class userBBS
{
private:
    string nickname;
    string email;
    string salt;
    string passwordDigest;
    string counter;

public:
    // Costruttore di default
    userBBS() {}

    // Costruttore che inizializza nickname, salt, passwordDigest, email e counter
    userBBS(string newNickname, string salt, string newPasswordDigest, string newEmail, string newCounter = "0")
    {
        this->nickname = newNickname;
        this->email = newEmail;
        this->salt = salt;
        this->passwordDigest = newPasswordDigest;
        this->counter = newCounter;
    }

    // Metodo set per impostare il valore di nickname
    void setNickname(string newNickname)
    {
        nickname = newNickname;
    }

    // Metodo set per impostare il valore di passwordDigest
    void setPasswordDigest(string newPasswordDigest)
    {
        passwordDigest = newPasswordDigest;
    }

    void setEmail(string newEmail)
    {
        this->email = newEmail;
    }

    void setSalt(string salt)
    {
        this->salt = salt;
    }

    void setCounter(string c)
    {
        this->counter = c;
    }

    void setCounter(uint64_t c)
    {
        this->counter = to_string(c);
    }

    // Metodo get per ottenere il valore di nickname
    string getNickname()
    {
        return this->nickname;
    }

    string getEmail()
    {
        return this->email;
    }

    // Metodo get per ottenere il valore di passwordDigest
    string getPasswordDigest()
    {
        return this->passwordDigest;
    }

    string getSalt()
    {
        return this->salt;
    }

    string getCounter()
    {
        return this->counter;
    }

    uint64_t getUintCounter()
    {
        return stoull(this->counter);
    }

    void incrCounter(uint64_t howMuch = 1)
    {
        uint64_t count = stoull(this->counter) + howMuch;
        this->counter = to_string(count);
    }

    void concatenateFields(string &str)
    {
        ostringstream oss;
        const char delimiter = '-';
        oss << this->nickname.length() << delimiter
            << this->email.length() << delimiter
            << this->salt.length() << delimiter
            << this->passwordDigest.length() << delimiter
            << this->counter.length() << delimiter
            << this->nickname
            << this->email
            << this->salt
            << this->passwordDigest
            << this->counter;
        str = oss.str();
    }

    void deconcatenateAndAssign(string &input)
    {
        if (input.size() <= 15)
        {
            return;
        }

        vector<string> stringVector;
        this->deconcatenateFields(stringVector, input);
        if (stringVector.size() == 5)
        {
            this->nickname = stringVector[0];
            this->email = stringVector[1];
            this->salt = stringVector[2];
            this->passwordDigest = stringVector[3];
            this->counter = stringVector[4];
        }
    }

    void deconcatenateFields(vector<string> &result, string &input)
    {
        result.clear();
        istringstream iss(input);
        string part;

        // Read the lengths
        int lengthNickname, lengthEmail, lengthSalt, lengthPasswordDigest, lengthCounter;
        getline(iss, part, '-');
        lengthNickname = stoi(part);
        getline(iss, part, '-');
        lengthEmail = stoi(part);
        getline(iss, part, '-');
        lengthSalt = stoi(part);
        getline(iss, part, '-');
        lengthPasswordDigest = stoi(part);
        getline(iss, part, '-');
        lengthCounter = stoi(part);

        // Read the actual fields based on the lengths
        int currentPos = iss.tellg();
        result.push_back(input.substr(currentPos, lengthNickname));
        currentPos += lengthNickname;
        result.push_back(input.substr(currentPos, lengthEmail));
        currentPos += lengthEmail;
        result.push_back(input.substr(currentPos, lengthSalt));
        currentPos += lengthSalt;
        result.push_back(input.substr(currentPos, lengthPasswordDigest));
        currentPos += lengthPasswordDigest;
        result.push_back(input.substr(currentPos, lengthCounter));
    }
};

#endif
