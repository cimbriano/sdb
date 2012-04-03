import java.security.*;

public class MakeDeposit extends ProtocolMessage {
    public double depositAmt;

    public MakeDeposit(double amt, int seq) {
	sequenceNumber = seq;
	depositAmt = amt;
    }
}