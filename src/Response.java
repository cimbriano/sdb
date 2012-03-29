import java.security.*;

public class Response extends ProtocolMessage {
    public int nonce;

    public Response(int nonce, int seq) {
	sequenceNumber = seq;
	this.nonce = nonce;
    }
}