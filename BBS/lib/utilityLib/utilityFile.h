#include <string>
#include <fstream>
#include <vector>
#include <iostream>

using namespace std;

#ifndef UTILITYFILE_H
#define UTILITYFILE_H

// deconcatenate fields of a message or user
void deconcatenateFields(vector<string> &ret, string &input)
{
    char delimiter = '-';
    size_t pos = input.find(delimiter); // Find the position of the first delimiter character

    while (pos != std::string::npos)
    {

        std::string parte = input.substr(0, pos); // get the first substring before the delimiter
        ret.push_back(parte);                     // add the substring to the vector
        input = input.substr(pos + 1);            // remove the extracted substring from the original string
        pos = input.find(delimiter);              // find the new position of the next delimiter character
    }
    ret.push_back(input); // add the last substring to the vector
}

// clear the entire content of the file
void clearFileContent(const string &filename)
{
    ofstream userFile(filename, ios::trunc); // open the file in trunc mode
    if (userFile.is_open())
    {
        userFile.close(); // close the empty file
    }
    else
    {
        cout << "Error during the file opening" << endl;
    }
}

#endif