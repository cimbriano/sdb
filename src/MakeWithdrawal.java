import java.security.*;

public class MakeWithdrawal extends ProtocolMessage {
    public MakeWithdrawal(int seq) {
	sequenceNumber = seq;
    }
}