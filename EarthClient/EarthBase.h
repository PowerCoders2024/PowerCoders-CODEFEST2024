//
// Created by danny on 7/28/24.
//

#ifndef EARTHBASE_H
#define EARTHBASE_H
#include <wolfssl/options.h>
#include <iostream>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <filesystem>
#include <string>
#include <wolfssl/wolfcrypt/types.h>

#include "../CryptoUser/CryptoUser.h"


class EarthBase : public CryptoUser{
public:
    EarthBase() : CryptoUser() {};


};



#endif //EARTHBASE_H
