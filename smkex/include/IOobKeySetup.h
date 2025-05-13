#ifndef __MP_IOOBKEYSETUP__
#define __MP_IOOBKEYSETUP__

#include <string>

class IOobKeySetup {
public:
    /**
     * @brief Get out-of-band key for ID
     * @param[in] buddy Buddy identity
     * @param[out] key Crypto key
     * @param[in] key_len Crypto key length
     * 
     * @return TRUE on success, FALSE otherwise  
     */
    virtual bool getKeyForBuddy(const std::string &buddy, char *key, int keyLen) = 0;
};

#endif /* __MP_IOOBKEYSETUP__ */