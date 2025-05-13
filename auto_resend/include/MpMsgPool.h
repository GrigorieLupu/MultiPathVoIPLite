

#ifndef __MP_MSGPOOL_H__
#define __MP_MSGPOOL_H__

#include "MpMsgPayload.h"
#include <deque>

class MpMsgPool {
private:
	std::deque<MpMsgPayload> messages_; ///< Unsent messages for the above serial
	long weight_; ///< User weight (this parameter will give the message sending priority)
	bool mutableWeight_; ///< Weight is mutable or not
	bool dirty_; ///< If this pool is dirty or not
public:
	/**
	 * @brief Ctor
	 * @param[in] message Message to be added to the user queue
	 * @return none
	 */
	MpMsgPool(MpMsgPayload const& message);
	/**
	 * @brief Dtor
	 * @return none
	 */
	~MpMsgPool();
	/**
	 * @brief Set weight
	 * @param[in] weight Weight
	 * @return none
	 */
	void setWeight(int weight) {
		weight_ = weight < 0 ? 0 : weight;
	}
	/**
	 * @brief Get weight
	 * @return Weight
	 */
	long getWeight() const {
		return weight_;
	}
	/**
	 * @brief Set if weight is mutable or not
	 * @param[in] mutableWeight TRUE if weight is mutable, FALSE otherwise
	 * @return none
	 */
	void setMutableWeight(bool mutableWeight) {
		mutableWeight_ = mutableWeight;
	}
	/**
	 * @brief Get weight mutability
	 * @return Weight mutability
	 */
	bool isMutableWeight() const {
		return mutableWeight_;
	}
	/**
	 * @brief Add an unsent message to this user queue
	 * @param[in] message Message to be added to the queue
	 * @return none
	 */
	void addMessage(MpMsgPayload const& message);
	/**
	 * @brief Delete the first message from the queue
	 * @return none
	 */
	void rmMessage(int msgId);
	/**
	 * @brief Get the first message in the queue
	 * @return Message
	 */
	const MpMsgPayload getMessage(bool autoResendEnabled);

	std::deque<MpMsgPayload>& getAllMessages() {
		return messages_;
	}
	/**
	 * @brief Get the number of unsent messages
	 * @return Number of unsent messages
	 */
	int getUnsentMsgNumber() const {
		return (int) messages_.size();
	}
	/**
	 * @brief Test if a certain message is added in this pool
	 * @param[in] msgId Message ID
	 * @return TRUE if message is added
	 */
	bool isMessageAdded(int msgId);
	/**
	 * @brief Mark pool as dirty
	 * @return none
	 */
	void markAsDirty() {
		dirty_ = true;
	}
	/**
	 * @brief Mark pool as clean
	 * @return none
	 */
	void markAsClean() {
		dirty_ = false;
	}
	/**
	 * @brief Test if pool is dirty
	 * @return TRUE if dirty
	 */
	bool isDirty() const {
		return dirty_;
	}
	/**
	 * @brief Get index for message with UID
	 * @param[in] msgUID message UID
	 * @return index or -1 if message was not found
	 */
	int getIndexForUID(int msgUID);
	/**
	 * @brief Get processed status for a given message
	 * @param[in] msgUID Message UID
	 * @return processed status TRUE or FALSE
	 */
	bool getProcessedStatusAt(int msgUID);
	/**
	 * @brief Test if pool is empty
	 * @return TRUE if pool is empty, FALSE otherwise
	 */
	bool isPoolEmpty();
	/**
	 * @brief Mark message as unprocessed
	 * @param[in] msgUID Message UID
	 * @return none
	 */
	void markMsgAsUnprocessed(int msgUID);
	/**
	 * @brief Mark message as processed
	 * @param[in] msgUID Message UID
	 * @return none
	 */
	void markMsgAsProcessed(int msgUID);
};

#endif /* __MP_MSGPOOL_H__ */
