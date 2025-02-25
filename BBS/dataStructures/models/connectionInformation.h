#include "../../lib/utilityLib/timestampLibrary.h" // Assumo che questa libreria definisca getCurrentTimestamp()
using namespace std;

#ifndef CONNECTIONINFORMATION_H
#define CONNECTIONINFORMATION_H

#define CONNECTION_VALIDITY_PERIOD 60 * 20 // 20 minutes

class connectionInformation
{
private:
    uint64_t socketDescriptor;
    string nickname;
    string loginTimestamp;
    string lastActivityTimeStamp;
    uint8_t logged;

public:
    connectionInformation()
    {
    }

    connectionInformation(int sd, string nickname, string login, string actv, bool logg)
    {
        this->socketDescriptor = sd;
        this->nickname = nickname;
        this->loginTimestamp = login;
        this->lastActivityTimeStamp = actv;
        this->logged = logg;
    }

    void refreshLogin(int sd)
    {
        this->socketDescriptor = sd;
        this->loginTimestamp = getCurrentTimestamp();
        this->lastActivityTimeStamp = this->loginTimestamp;
        this->logged = true;
    }

    void refreshLogout()
    {
        this->refreshLastActionTimestamp();
        this->logged = false;
    }

    void refreshLastActionTimestamp()
    {
        this->lastActivityTimeStamp = getCurrentTimestamp();
    }

    // Metodi 'get' per ottenere i valori degli attributi
    uint64_t getSocketDescriptor()
    {
        return socketDescriptor;
    }

    string getNickname()
    {
        return nickname;
    }

    string getLoginTimestamp()
    {
        return loginTimestamp;
    }

    string getLastActivityTimeStamp()
    {
        return lastActivityTimeStamp;
    }

    uint8_t getLogged()
    {
        return logged;
    }

    // Metodi 'set' per impostare i valori degli attributi
    void setSocketDescriptor(int sd)
    {
        socketDescriptor = sd;
    }

    void setNickname(const string &nick)
    {
        nickname = nick;
    }

    // In caso si voglia cambiare manualmente il timestamp di login
    void setLoginTimestamp(const string &timestamp)
    {
        loginTimestamp = timestamp;
    }

    // In caso si voglia cambiare manualmente il timestamp di ultima attività
    void setLastActivityTimeStamp(const string &timestamp)
    {
        lastActivityTimeStamp = timestamp;
    }

    // In caso si voglia impostare manualmente lo stato di log-in
    void setLogged(bool value)
    {
        logged = value;
    }

    void setLogged(int value)
    {
        if (value == 0)
        {
            logged = 0;
        }
        else
        {
            logged = 1;
        }
    }

    void setLogged(uint64_t value)
    {
        if (value == 0)
        {
            logged = 0;
        }
        else
        {
            logged = 1;
        }
    }
    void setLogged(uint8_t value)
    {
        logged = value;
    }

    bool checkValidityOfTheConnection()
    {
        const string currentTs = getCurrentTimestamp();
        const int diffLast = secondDifference(currentTs, this->lastActivityTimeStamp);
        const int diffLog = secondDifference(currentTs, this->loginTimestamp);
        if (
            diffLog < 0 ||
            diffLast < 0 ||
            diffLast > CONNECTION_VALIDITY_PERIOD)
        {
            return false;
        }
        else
        {
            return true;
        }
    }

    void concatenateFields(string &str)
    {
        ostringstream oss;
        const char delimiter = '-';
        oss << this->socketDescriptor << delimiter
            << this->nickname.length() << delimiter
            << this->loginTimestamp.length() << delimiter
            << this->lastActivityTimeStamp.length() << delimiter
            << static_cast<int>(this->logged) << delimiter
            << this->nickname
            << this->loginTimestamp
            << this->lastActivityTimeStamp;
        str = oss.str();
    }

    void deconcatenateAndAssign(string &input)
    {
        vector<string> stringVector;
        this->deconcatenateFields(stringVector, input);
        if (stringVector.size() == 4)
        {
            this->nickname = stringVector[0];
            this->loginTimestamp = stringVector[1];
            this->lastActivityTimeStamp = stringVector[2];
            this->logged = static_cast<uint8_t>(stoi(stringVector[3]));
        }
    }

    void deconcatenateFields(vector<string> &result, string &input)
    {
        result.clear();
        istringstream iss(input);
        string part;

        // Read the descriptor and logged status
        getline(iss, part, '-');
        this->socketDescriptor = stoull(part);
        int loggedInt;
        iss.seekg(input.find_last_of('-') + 1);
        iss >> loggedInt;
        this->logged = static_cast<uint8_t>(loggedInt);

        // Read the lengths
        int lengthNickname, lengthLoginTimestamp, lengthLastActivityTimeStamp;
        iss.seekg(iss.beg);
        getline(iss, part, '-');
        getline(iss, part, '-');
        lengthNickname = stoi(part);
        getline(iss, part, '-');
        lengthLoginTimestamp = stoi(part);
        getline(iss, part, '-');
        lengthLastActivityTimeStamp = stoi(part);

        // Read the actual fields based on the lengths
        result.push_back(input.substr(iss.tellg(), lengthNickname));
        iss.seekg(iss.tellg() + streampos(lengthNickname));
        result.push_back(input.substr(iss.tellg(), lengthLoginTimestamp));
        iss.seekg(iss.tellg() + streampos(lengthLoginTimestamp));
        result.push_back(input.substr(iss.tellg(), lengthLastActivityTimeStamp));
    }
};

#endif