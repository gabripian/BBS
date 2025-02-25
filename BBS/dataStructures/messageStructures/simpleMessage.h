#include <iostream>
#include <string>
#include <sstream>
#include <vector>
using namespace std;

#ifndef SIMPLEMESSAGE_H
#define SIMPLEMESSAGE_H


class SimpleMessage {
private:
    string content;
    size_t contentDim;

public:
    // Costruttore di default
    SimpleMessage(){}

    // Costruttore parametrizzato
    SimpleMessage(const string& content){
        this->setContent(content);
    }

    // Getter e Setter per contentDim
    size_t getContentDim() const {
        return contentDim;
    }

    // Getter e Setter per content
    string getContent() const {
        return content;
    }

    void setContent(const string& content) {
        this->content = content;
        this->contentDim = this->content.size();
    }

    // Metodo per concatenare i campi in una stringa
    void concatenateFields(string &str) const {
        ostringstream oss;
        const char delimiter = '-';
        oss << contentDim << delimiter << content;
        str = oss.str();
    }

    // Metodo per deconcatenare i campi da una stringa
    void deconcatenateFields(vector<string> &result, const string &input) const {
        result.clear();
        istringstream iss(input);
        string part;

        // Leggi contentDim
        getline(iss, part, '-');
        size_t lengthContent = stoi(part);

        // Leggi content
        result.push_back(input.substr(iss.tellg(), lengthContent));
    }

    // Metodo per deconcatenare e assegnare i campi da una stringa
    void deconcatenateAndAssign(const string &input) {
        vector<string> stringVector;
        this->deconcatenateFields(stringVector, input);
        if (stringVector.size() == 1) {
            this->content = stringVector[0];
            this->contentDim = content.size();
        }
    }
};

#endif
