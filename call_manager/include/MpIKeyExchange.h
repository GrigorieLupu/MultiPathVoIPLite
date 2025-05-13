#ifndef __MP_IKEY_EXCHANGE_H__
#define __MP_IKEY_EXCHANGE_H__

class MpIKeyExchange {
public:
	/**
	 * @brief Start key exchange --> if is called for the first time sends callback to OS
	 * @return NONE
	 */
	virtual void startKeyExchange() = 0;
	/**
	 * @brief Stop Key exchange-->handshake was successful
	 * @return NONE
	 */
	virtual void stopKeyExchange() = 0;

	/**
	 * @brief Dtor
	 * @return none
	 */
	virtual ~MpIKeyExchange() {
	}
};

#endif /* __MP_IKEY_EXCHANGE_H__ */
