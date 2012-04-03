public class TranMessage extends LogMessage {

        private SignedMessage signedMsg;

    public TranMessage(String message, int session, SignedMessage msg) {
       	super(message, session);
	signedMsg = msg;	
    }
}