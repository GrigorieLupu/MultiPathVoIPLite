#ifndef __MP_SMKEXSTATE_H__
#define __MP_SMKEXSTATE_H__


/**
 * Class only used for the SMKEX states, to have a scope.
 */
class SmkexState{

  public:

	/** @brief We enumerate the states of the end-to-end SMKEX state machine 
	 *  Each SessionInfo (the SessionInfo for each buddy) is in exactly one of these states at any time
	 * Each SessionInfo also contains the  information whether the current user is the initiator of the end-to-end
   * SMKEX key exchange for the session
   * (in case the session is lost this can help in deciding who starts again the key exchange as initiator) 
	 */
	enum state{
    STATENotConnected = 0,
    STATEWaitKey,
    STATEWaitNonce,
    STATEWaitNonceH,
    STATEConnected};
};


#endif /* __MP_SMKEXSTATE_H__*/
