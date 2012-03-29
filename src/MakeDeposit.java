import java.security.*;

public class MakeDeposit extends ProtocolMessage {
    public int depositAmt;

    public MakeDeposit(int amt, int seq) {
	sequenceNumber = seq;
	depositAmt = amt;
    }
}