import java.security.*;

public class MakeWithdrawal extends ProtocolMessage {
    double withdrawalAmt;

    public MakeWithdrawal(double amt, int seq) {
	sequenceNumber = seq;
	withdrawalAmt = amt;
    }
}