#include <iostream>
#include <sstream>
#include <getopt.h>

// #include <strings.h>
#include <string.h>

using namespace std;

string generator = "10001000010100001"; //x16 + x12 + x7 + x5 + 1
string message;
string output = "";
bool addShiftZeros;


char XOR(char a, char b){
    if (a != b) return '1';
    else return '0';
}

string makeCRC(string msg, string gen){
    char remainder[50];
    char tmp[50];
    int msgLen = msg.length();
    int genLen = gen.length();
    int genMinus = genLen - 1;
    int resLen;

    // shifting (pad zeros at end of message)
    for (int x = 0; x < genMinus; x++) {
        msg[x + msgLen] = '0';
    }             
    
    resLen = msgLen + genMinus;                
    
    // look at genLen bits of msg for the division
    for (int x = 0; x < genLen; x++){
        remainder[x] = msg[x];
    }
                       
    // performing the division
    for (int i = genLen; i <= resLen; i++) {
        for (int x = 0; x < genLen; x++) {
            tmp[x] = remainder[x];   
        }
                     
        if (remainder[0] == '1') {
            for (int x = 0; x < genMinus; x++) {
                remainder[x] = XOR(tmp[x + 1], gen[x + 1]);
            }    
        }

        else {    
            for (int x = 0; x < genMinus; x++) {
                remainder[x] = tmp[x + 1];
            }   
        }

        if (i == resLen) {
            remainder[genMinus] = '\0';
            
        }
                    
        else {
            remainder[genMinus] = msg[i];
        }    
    }

    //msg += remainder;
    
    //cout <<"CRC="<< remainder << endl;
    //cout <<"msgword="<< msg << endl;
    return remainder;
}

int main (int argc, char **argv) {
    int c;
    int state = 0;

    while ((c = getopt(argc,argv, "c:v:f:t:")) != -1) {
        switch(c) {
            case 'c':
                state = 1;
                // addShiftZeros = true;
                message = optarg;
                break;
            case 'v':
                state = 2;
                message = optarg;
                break;
            case 'f':
                state = 3;
                // addShiftZeros = true;
                message = optarg;
                break;
            case 't':
                state = 4;
                // addShiftZeros = false;
                message = optarg;
                break;

            default:
                return 2;
        }
    }

    if (state == 1) { // -c flag
        string output = makeCRC(message, generator);
        cout << output << endl;
        return 0;
    }
    
}