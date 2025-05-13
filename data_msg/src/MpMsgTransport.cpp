#include "MpMsgTransport.h"
#include "MpBaseService.h"

MpMsgTransport::MpMsgTransport() :
		msgLock_("MpMsgTransport Message lock"), msgNotif_(MP_NULL), msg_(
				"null", MpBuffer(), 0, 0, 0, MP_TYPE_MESSAGE, false), counter_(
				0) {
	MP_LOG1("Ctor");
}

MpMsgTransport::~MpMsgTransport() {
	MP_LOG1("Dtor");
}

void MpMsgTransport::sendMessage(const MpMsgPayload& message) {
	MP_LOG1("Send message");
	msgLock_.lock();
	msg_ = message;
	counter_ = msg_.getNumberOfRetries();
	if (counter_ <= 0) {
		msgLock_.unlock();
		return;
	}
	/*Get transport message payload*/
	MpBuffer messagePayload = msg_.getTransportPayload();
	/*Send message now*/
	MpService::instance()->getSIPStack()->sendMsg(msg_.getUserSerial().c_str(),
			messagePayload.getPayload(), messagePayload.getLen(), (void*) 0);
	msgLock_.unlock();
}

void MpMsgTransport::setMsgTransportNotif(MpIMsgTransportNotif* msgNotif) {
	MP_LOG1("Set transport notifier");
	msgNotif_ = msgNotif;
}

void MpMsgTransport::onSendMsgDone(mp_status_t xferStatus) {
	msgLock_.lock();
	do {
		/*Message was deleted*/
		if (!msg_.getNumberOfRetries())
			break;
		--counter_;
		/*Try another transfer if possible*/
		if (xferStatus != MP_MESSAGE_SENT && counter_ > 0) {
			/*Send message now*/
			/*Get transport message payload*/
			MpBuffer messagePayload = msg_.getTransportPayload();
			/*Send message now*/
			pj_thread_sleep(MP_MSG_TRANSPORT_SLEEP);
			MpService::instance()->getSIPStack()->sendMsg(
					msg_.getUserSerial().c_str(), messagePayload.getPayload(),
					messagePayload.getLen(), (void*) 0);
		} else {
			msg_.setNumberOfRetries(0);
			/*Sanity check for notifier*/
			if (msgNotif_)
				msgNotif_->messageStatus(msg_, xferStatus);
		}
	} while (0);
	msgLock_.unlock();
}

void MpMsgTransport::removeMessageForSerial(std::string const& receiverSerial) {
	msgLock_.lock();

	if (msg_.getUserSerial() == receiverSerial)
		msg_.setNumberOfRetries(0);

	msgLock_.unlock();
}
