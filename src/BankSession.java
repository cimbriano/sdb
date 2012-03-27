import java.net.*;
import java.io.*;
import java.security.*;

public class BankSession implements Session, Runnable {
    private Socket s;
    private ObjectOutputStream os;
    private ObjectInputStream is;

    private AccountDB accts;
    private Crypto crypto;
    private PrivateKey kPrivBank;
    private PublicKey  kPubBank;

    // These fields are initialized during authentication
    private Key kSession;
    private Account currAcct;
    private String atmID;

    // Add additional fields you need here

    BankSession(Socket s, AccountDB a, KeyPair p)
	throws IOException
    {
	this.s = s;
	OutputStream out =  s.getOutputStream();
	this.os = new ObjectOutputStream(out);
	InputStream in = s.getInputStream();
	this.is = new ObjectInputStream(in);
	this.accts = a;
	this.kPrivBank = p.getPrivate();
	this.kPubBank = p.getPublic();
	this.crypto = new Crypto();
    }

    public void run() {
	try {
	    if (authenticateUser()) {
		while (doTransaction()) {
		    // loop
		}
	    }
	    is.close();
	    os.close();
	} 
	catch (Exception e) {
	    e.printStackTrace();
	}
    }
    
    // Interacts with an ATMclient to 
    // (1) Authenticate the user
    // (2) If the user is valid, establish session key and any
    //     additional information needed for the protocol.
    // (3) Maintain a log of whether the login attempt succeeded
    // (4) Returns true if the user authentication succeeds, false otherwise
    public boolean authenticateUser() {

	// replace this with the appropriate code
	return false;
    }

    // Interacts with an ATMclient to 
    // (1) Perform a transaction 
    // (2) or end transactions if end-of-session message is received
    // (3) Maintain a log of the information exchanged with the client
    public boolean doTransaction() {

	// replace this code to carry out a bank transaction
	return false;
    }
}

