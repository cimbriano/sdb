import java.security.*;

public class Quit extends ProtocolMessage {
    public Quit(int seq) {
	sequenceNumber = seq;
    }
}