#ifndef __SMKEX_RECORD_H__
#define __SMKEX_RECORD_H__
#include <stdint.h>
#include <iostream>
#include <cstring>
#include <stdint.h>
#include <string>

#define SMKEX_T4M_PROTOCOL_VERSION 0x01
#include <time.h>

enum SMKEX_T4M_Type {
  empty = 0,
  handshakeKey = 1,
  handshakeNonce = 2,
  handshakeNonceH = 3,
  alert = 4,
  handshakeKyberCiphertext = 5,
  verticalRatchetInitiate = 6,    // Inițiază vertical ratchet cu noua cheie DH
  verticalRatchetResponse = 7     // Răspuns la vertical ratchet cu cheia DH
};


class SmkexT4mRecord{    

  private:
    uint8_t _version;
    int64_t _timestamp;
    std::string _dest;
    std::string _src;
    SMKEX_T4M_Type _type; // uint8_t
    uint32_t _dlen;
    unsigned char* _data;

    void clearRecord();


  public:

    /* Constructors */

    /**
     * @brief Initialize a SmkexT4mRecord object from the given data (using std::strings as input for sender and receiver)
     * @param[in] timestamp: timestamp
     * @param[in] dest receiver 
     * @param[in] src sender  
     * @param[in] type type of message
     * @param[in] version version of Smkex protocol
     * @param[in] length  length of record data
     * @param[in] data  pointer to the data
    */
    SmkexT4mRecord(int64_t timestamp, std::string dest, std::string src, SMKEX_T4M_Type type,
                   uint8_t version, uint32_t dlen, const unsigned char *data);

    /**
     * @brief constructs a record from a serialized record.
     * 
     * Note: if a record cannot be created from the given input
     * (e.g. insufficient or corrupted data, then the resulting object
     * will have an empty type).
     *
     * @param buf: a pointer to the buffer containing a record.
     * @param len: length of the data in buf
    */
    SmkexT4mRecord(const char buf[], unsigned int len);

    /* Destructor */
    ~SmkexT4mRecord();

    // copy operator
    SmkexT4mRecord& operator=(const SmkexT4mRecord& other);

    /* Getter functions */

    inline uint8_t getVersion() const {return _version;}
    inline int64_t getTimestamp() const {return _timestamp;}
    std::string getDest() const {return _dest;}
    std::string getSrc() const {return _src;}
    SMKEX_T4M_Type getType() const {return _type;}  // uint8_t
    uint32_t getLength() const; // total size of this object's fields


    /**
     * @brief Returns the data field
     * @param pre-allocated data buffer to store a copy of the data field. Pass NULL to get the data length.
     * @return: length of data field.
     */
    uint32_t getData(unsigned char dataptr[]) const;

    /**
     * @brief Parses a string of bytes into a SmkexT4mRecord object.
     *
     * @param buf: the input buffer to be parsed.
     * returns the parsed object or an empty one if parsing failed.
     */
    //SmkexT4mRecord parseRecord(const unsigned char buf[]) const;

    /**
     * @brief Check if we have an SmkexT4Record available in the given structure.
     *
     * @param buf: the input buffer to 
     * returns true if a record can be parsed from the given buffer, false otherwise.
     */
    //bool isRecord(const unsigned char buf[]) const;

    /**
     * @brief Serialize this SmkexT4MRecord object * 
     * @param pre-allocated data buffer to store the serialization of this object
     * @return: length of serialized object if successful, 0 otherwise.
     */
    int serializeRecord(unsigned char buf[]) const;

    /**
     * @brief prints information of the record 
     * @param r: to the record
     * @return NONE
    */
    void printRecord() const;


}; 
#endif





