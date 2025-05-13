#ifndef __MP_ICALLTIMEOUT_H__
#define __MP_ICALLTIMEOUT_H__

class MpICallTimeout {
public:
	/**
	 * @brief End call (RTP watchdog inactivity)
	 * @return none
	 */
	virtual void endWatchdogCall() = 0;
	/**
	 * @brief Set call timeout to do callback (avoid repeated callbacks)
	 * @return none
	 */
	virtual void setDoCallback() = 0;
	/**
	 * @brief Dtor
	 * @return none
	 */
	virtual ~MpICallTimeout() {
	}
};

#endif /* __MP_ICALLTIMEOUT_H__ */
