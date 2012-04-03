import java.security.*;

public class Challenge extends ProtocolMessage {
    public int nonce;

    public Challenge(int nonce, int seq) {
	sequenceNumber = seq;
	this.nonce = nonce;
    }
}