public class TranMessage extends LogMessage {
    public ProtocolMessage pm;

    public TranMessage(String message, int session, ProtocolMessage pm) {
	super(message, session);
	this.pm = null;
    }
}