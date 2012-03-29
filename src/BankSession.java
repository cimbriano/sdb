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
    private PublicKey kPubUser;
    private int seqNumber;

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
	seqNumber = sr.nextInt();

	try {
	    System.out.println("Waiting for an AuthInit...");
	    
	    AuthInit a = (AuthInit) crypto.decryptRSA(nextObject(), kPrivBank);

	    currAcct = accts.getAccount(a.accNumber);
	    atmID = a.atmID;
	    kPubUser = currAcct.getKey();

	    /*
	     *
	     */

	    System.out.println("Got an AuthInit; sending challenge.");

	    Challenge c = new Challenge(sr.nextInt(), seqNumber++);
	    os.writeObject( crypto.encryptRSA(c, kPubUser) );

	    /*
	     *
	     */

	    Response r = (Response) crypto.decryptRSA(nextObject(), kPrivBank);

	    System.out.print("Received response; ");

	    if (ProtocolMessage.validate(a, r) == false) {
		return false;
	    } else if (c.nonce != r.nonce) {
		System.out.println("challenge failed.");
		return false;
	    }

	    System.out.println("challenge passed.");

	    /*
	     *
	     */
	    
	    System.out.print("Waiting for challenge; ");

	    c = (Challenge) crypto.decryptRSA(nextObject(), kPrivBank);

	    if (ProtocolMessage.validate(r, c) == false)
		return false;

	    r = new Response(c.nonce, seqNumber++);

	    os.writeObject( crypto.encryptRSA(r, kPubUser) );

	    System.out.println("answered.");

	    /*
	     *
	     */

	    System.out.println("Authenticated! Sending session key.");

	    kSession = crypto.makeAESKey();
	    os.writeObject( crypto.encryptRSA(kSession, kPubUser) );	    	    
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

	System.out.println("Initiated session with ACCT#" + currAcct.getNumber() +
			   " on ATM " + atmID);

	return true;
    }

    // Interacts with an ATMclient to 
    // (1) Perform a transaction 
    // (2) or end transactions if end-of-session message is received
    // (3) Maintain a log of the information exchanged with the client
    public boolean doTransaction() {
	try {
	    byte[] e = (byte[]) is.readObject();
	    SignedMessage m = (SignedMessage) crypto.decryptAES(e, kSession);

	    if (crypto.verify(m.msg, m.signature, kPubUser) == false)
		return false;

	    ProtocolMessage pm = (ProtocolMessage) m.getObject();		

	    if (pm instanceof MakeDeposit)
		return doDeposit((MakeDeposit) pm);
	    else if (pm instanceof MakeWithdrawal)
		return doWithdrawal((MakeWithdrawal) pm);
	    else if (pm instanceof CheckBalance)
		return doBalance((CheckBalance) pm);

	} catch (IOException e) {
	    e.printStackTrace();
	    return false;
	} catch (ClassNotFoundException e) {
	    e.printStackTrace();
	    return false;
	} catch (KeyException e) {
	    e.printStackTrace();
	    return false;
	} catch (SignatureException e) {
	    e.printStackTrace();
	    return false;
	}

	return true;
    }

    private boolean doWithdrawal(MakeWithdrawal withdrawal) {
	return false;
    }

    private boolean doBalance(CheckBalance balance) {
	return false;
    }

    private boolean doDeposit(MakeDeposit deposit) {
	return false;
    }

    private byte[] nextObject() throws IOException, ClassNotFoundException {
	return (byte[]) is.readObject();
    }
}

