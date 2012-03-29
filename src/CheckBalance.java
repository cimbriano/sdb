import java.security.*;

public class CheckBalance extends ProtocolMessage {
    public CheckBalance(int seq) {
	sequenceNumber = seq;
    }
}