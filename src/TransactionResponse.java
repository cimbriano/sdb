import java.security.*;

public class TransactionResponse extends ProtocolMessage {
    public double balance;

    public TransactionResponse(double amt, int seq) {
	sequenceNumber = seq;
	balance = amt;
    }
}