import java.security.*;

public class Auth_Init extends ProtocolMessage {
    public String accNumber;

    public Auth_Init(String accNumber) {
	SecureRandom sr = new SecureRandom();
	
	sequenceNumber = sr.nextInt();
	type = ProtocolType.AUTH_INIT;

	this.accNumber = accNumber;
    }

}