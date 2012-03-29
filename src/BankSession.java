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
	SecureRandom sr = new SecureRandom();
	int seqNumber = sr.nextInt();

	try {
	    print("Waiting for an AuthInit...");

	    byte[] e = (byte[]) is.readObject();
	    AuthInit a = (AuthInit) crypto.decryptRSA(e, kPrivBank);

	    currAcct = accts.getAccount(a.accNumber);
	    atmID = a.atmID;

	    PublicKey kUser = currAcct.getKey();

	    /*
	     *
	     */

	    print("Got an AuthInit, sending challenge.");

	    Challenge c = new Challenge(sr.nextInt(), seqNumber++);
	    byte[] txt = crypto.encryptRSA(c, kUser);

	    os.writeObject(txt);

	    /*
	     *
	     */

	    print("Received response.");

	    e = (byte[]) is.readObject();
	    Response r = (Response) crypto.decryptRSA(e, kPrivBank);

	    if (ProtocolMessage.validate(a, r) == false)
		return false;

	    if (c.nonce != r.nonce) {
		print("Challenge failed.");
		return false;
	    }

	    print("Challenge passed.");

	    /*
	     *
	     */

	    e = (byte[]) is.readObject();
	    c = (Challenge) crypto.decryptRSA(e, kPrivBank);

	    if (ProtocolMessage.validate(r, c) == false)
		return false;

	    /*
	     *
	     */

	    r = new Response(c.nonce, seqNumber++);
	    txt = crypto.encryptRSA(r, kUser);

	    os.writeObject(txt);

	    /*
	     *
	     */

	    print("Authenticated! Sending session key.");

	    kSession = crypto.makeAESKey();
	    txt = crypto.encryptRSA(kSession, kUser);

	    os.writeObject(txt);

	    System.out.println(kSession);
	    	    
	} catch (IOException e) {
	    e.printStackTrace();
	    return false;
	} catch (ClassNotFoundException e) {
	    e.printStackTrace();
	    return false;
	} catch (KeyException e) {
	    e.printStackTrace();
	    return false;
	} catch (AccountException e) {
	    e.printStackTrace();
	    return false;
	}

	return true;
    }

    // Interacts with an ATMclient to 
    // (1) Perform a transaction 
    // (2) or end transactions if end-of-session message is received
    // (3) Maintain a log of the information exchanged with the client
    public boolean doTransaction() {

	// replace this code to carry out a bank transaction
	return false;
    }

    private void print(String txt) {
	System.out.println(txt);
    }
}

