#ifndef __MP_ICALL_TIMER_H__
#define __MP_ICALL_TIMER_H__

/*!
 Used to handle the correct execution of call states and to provide
 a fallback method.
 
 @class MpCallTimer
 @warning Do not use for anything besides this!
 */
class MpICallTimer {
public:
	/*!
	 Starts or reintialize timer.
	 
	 @param -
	 @return TRUE/FALSE based on successfully starting the timer
	 */
	virtual void startTimer(float t) = 0;
	
	/*!
	 Check if timer is active.
	 
	 @param -
	 @return TRUE/FALSE based on the current state of the timer
	 */
	virtual bool timerIsActive() = 0;
	
	/*!
	 Stops timer.
	 
	 @param -
	 @return TRUE/FALSE based on successfully stopping the timer
	 */
	virtual void stopTimer() = 0;
	
	/*!
	 Callback function assigned to the timer. This is a fallback function.
	 If something goes wrong with the call, this function should be called
	 to force-close the call screen and to reset the connection with the server.
	 
	 @param -
	 @return -
	 */
	virtual void tickTimer() = 0;
	
	/*!
	 * @brief Dtor
	 * @return NONE
	 */
	virtual ~MpICallTimer() {
		
	}
	
};

#endif /* __MP_ICALL_TIMER_H__ */
