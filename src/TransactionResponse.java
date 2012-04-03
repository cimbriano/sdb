import java.security.*;

public class TransactionResponse extends ProtocolMessage {
    public String message; 
    public double balance;

    public TransactionResponse(String message, double amt, int seq) {
	this.message = message;
	balance = amt;
	sequenceNumber = seq;
    }

    public TransactionResponse(double amt, int seq) {
	sequenceNumber = seq;
	balance = amt;
	message = null;
    }
}