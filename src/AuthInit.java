import java.security.*;

public class AuthInit extends ProtocolMessage {
    public String accNumber;
    public String atmID;

    public AuthInit(String accNumber, String atmID, int seq) {
	sequenceNumber = seq;
	this.accNumber = accNumber;
	this.atmID = atmID;
    }
}