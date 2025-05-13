/** \file
 *  \brief  SmkexSessionInfo.c source file
 *
 *  This file implements the SmkexRecord structure functionalities
 *
 *  Authors:
 * 	  Liliana Grigoriu (liliana.grigoriu@upb.ro)
 *    Marios O. Choudary (marios.choudary@cs.pub.ro)
 *
 * 	Last update: August 2021
 *
 */

#include <iostream>
#include <string.h>
#include <cstring>
#include <vector>
#include <map>
#include <algorithm>
#include <string>
#include <sstream>
#include "SmkexRecord.h"  
#include "Smkex.h"
#include "logging.hpp"


namespace patch
{
    template < typename T > std::string to_string( const T& n )
    {
        std::ostringstream stm ;
        stm << n ;
        return stm.str() ;
    }
}


// Note: Best way is to use objects instead of pointers (see C++ RAII)
// i.e. make SmkexT4mRecord a class (as here)
// https://en.cppreference.com/w/cpp/language/raii
// See also this nice tutorial on memory management for C++
// https://www.bogotobogo.com/cplusplus/memoryallocation.php

SmkexT4mRecord::SmkexT4mRecord(int64_t timestamp, std::string dest, 
                   std::string src, SMKEX_T4M_Type type, uint8_t version, 
                   uint32_t dlen, const unsigned char *data){
      _version = version;
      if (timestamp==0){
        	time_t tt=time(NULL);
        	timestamp=(int64_t)tt;
      }
      _timestamp = timestamp;
      _dest = dest;
      _src = src;
      _type = type;
      _dlen = dlen;
      _data = new unsigned char[dlen];
      memcpy(_data, data, dlen);
}

// TODO: appply hton/ntoh functions if necessary
SmkexT4mRecord::SmkexT4mRecord(const char buf[], unsigned int len){
  
  std::string tmp2 = patch::to_string(len);
  
  int pos = 0;

  _version = 0;
  _timestamp = 0;
  _dest = "";
  _src = "";
  _type = SMKEX_T4M_Type::empty;
  _dlen = 0;

#if DEBUG
  printf("About to create record from serialized buffer with len %d\n", len);
#endif
  MP_LOG1("About to create record from serialized buffer with len\n");

  if (len < 16)
    MP_LOG1("In SmkexRecord constructor - I will exit now!\n");

  if (len < 16)
    return;
  
  MP_LOG1("In SmkexRecord constructor - After return statement!\n");
  MP_LOG1("About to print dest!\n");
  // if(buf != nullptr)
  //   MP_LOG2("Dest is: ", buf);
  // std::cout << "Size of uchar is: " << sizeof(unsigned char *) << '\n';

	_version= *(uint8_t *)buf;  //primul element, il memoreaza in version
  pos += sizeof(_version);

	_timestamp= *(int32_t *)(&buf[pos]); 
  
  MP_LOG1("After timestamp\n");

  pos += sizeof(_timestamp);
  _dest = (char*) (&buf[pos]);
#if DEBUG
  printf("_dest = %s\n", &buf[pos]);
#endif

  pos += _dest.length() + 1;
  _src = (char*) (&buf[pos]);

#if DEBUG
  printf("_src = %s\n", &buf[pos]);
#endif

  pos += _src.length() + 1;
	_type = (SMKEX_T4M_Type) *(uint8_t *)(&buf[pos]);
  pos += sizeof(_type);
	_dlen=*(uint32_t *) (&buf[pos]);
  pos += sizeof(_dlen);
  MP_LOG1("In Smkex record constructor - about to check pos!\n");

  if(pos+_dlen != len)
  {
#if DEBUG
    printf("Size missmatch. Pos = %d, _dlen = %d, len = %d\n", pos, _dlen, len);
#endif
  MP_LOG1("In Smkex record constructor - size missmatch!\n");
    _version = 0;
    _timestamp = 0;
    _dest = "";
    _src = "";
    _type = SMKEX_T4M_Type::empty;
    _dlen = 0;
    return;
  }
  _data = new unsigned char[_dlen];
  memcpy(_data, &buf[pos], _dlen);

  MP_LOG1("Successfully exited SmkexT4mRecord::SmkexT4mRecord constructor!\n");
}

SmkexT4mRecord::~SmkexT4mRecord(){
  if (_data != NULL)
  {
    delete[] _data;
    _data = NULL;
  }
}

SmkexT4mRecord& SmkexT4mRecord::operator=(const SmkexT4mRecord& other)
{
  printf("We are in the copy constructor of SmkexT4mRecord\n");

  if (this == &other)
     return *this;

  printf("and in SmkexT4mRecord(&other) we are not called by *this.... \n");

  _version = other.getVersion();
  _timestamp = other.getTimestamp();
  _dest = other.getDest();
  _src = other.getSrc();
  _type = other.getType();
  if(_dlen != other.getData(NULL))
  {
    delete[] _data;
    _data = NULL;   
    _dlen = 0;
    _data = new unsigned char[other.getData(NULL)];
    _dlen = other.getData(_data);
  }
  else
    other.getData(_data);

  return *this;
}

void SmkexT4mRecord::clearRecord()
{
  _version = 0;
  _timestamp = 0;
  _dest = "";
  _src = "";
  _type = SMKEX_T4M_Type::empty;
  _dlen = 0;
  if (_data != NULL)
  {
    delete[] _data;
    _data = NULL;
  }
}


uint32_t SmkexT4mRecord::getLength() const
{
  return sizeof(_version) + sizeof(_timestamp) + _dest.length() + 1 + _src.length() + 1 + sizeof(_type) + sizeof(_dlen) + _dlen;
}

uint32_t SmkexT4mRecord::getData(unsigned char dataptr[]) const
{
  if (dataptr != NULL)
    memcpy(dataptr, _data, _dlen);

  return _dlen;
}

// TODO: appply hton/ntoh functions if necessary
int SmkexT4mRecord::serializeRecord(unsigned char buf[]) const
{
  
  if (buf==NULL)
    return 0;

  int pos = 0;
  memcpy(&buf[pos], &(_version), sizeof(_version));
  pos += sizeof(_version);
  
  memcpy(&buf[pos], &(_timestamp), sizeof(_timestamp));
  pos += sizeof(_timestamp);
  
  memcpy(&buf[pos], _dest.c_str(), _dest.length());
  pos += _dest.length();
  buf[pos++] = 0;


  memcpy(&buf[pos], _src.c_str(), _src.length());
  pos += _src.length();
  buf[pos++] = 0;
  
  memcpy(&buf[pos], &(_type), sizeof(_type));
  pos += sizeof(_type);
  
  memcpy(&buf[pos], &(_dlen), sizeof(_dlen));
  pos += sizeof(_dlen);
  
  memcpy(&buf[pos], _data, _dlen);
  pos += _dlen;

  return pos;
}
    

void SmkexT4mRecord::printRecord() const{

  #ifdef ANDROID
    MP_LOG1("SMG-DBG:: printRecord:");
    MP_LOG2_INT("SMG-DBG:: Smkex protocol version: ", (int) _version);
    MP_LOG2_INT("SMG-DBG:: Smkex timestamp: ", (int) _timestamp);
    MP_LOG2("SMG-DBG:: Dest id: ", _dest.c_str());
    MP_LOG2("SMG-DBG:: Send id: ", _src.c_str());
    MP_LOG2_INT("SMG-DBG:: Type of record: ", (int) _type);
    MP_LOG2_INT("SMG-DBG:: Data length: ", (int) _dlen);
    MP_LOG2_HEX("SMG-DBG:: Data: ", _data, (int) _dlen);
    MP_LOG1("SMG-DBG:: Done printing smkexT4mRecord");
  #else
    cout<<"printRecord:\n";
    cout<<"Smkex protocol version: "<< _version<< "\n";
    cout<<"timestamp raw as int64_t: "<< _timestamp<< "\n";
    time_t t =(time_t) _timestamp;
    cout<<"timestamp formatted: "<< ctime((const time_t*)&t)<< "\n";
    cout<<"Dest id: "<< _dest<<"\n";
    cout<<"Send id: "<< _src<<"\n";
    cout<<"Type of record/message:" << _type << endl;
    cout<<"Data length: " << _dlen << endl;
    cout<<"Data: " << _dlen << endl;
    for(unsigned int k=0; k<_dlen; k++)
      printf("%02X", _data[k]);
    printf("\n");	
    cout<<"\n Done printing smkexT4mRecord\n";
  #endif

}
