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
    private ProtocolMessage prevMsg;
    private Log log;
    private int session;

    private static final String logFile = "log.bin";

    BankSession(Socket s, AccountDB a, KeyPair p, int session) throws IOException {
	this.s = s;
	OutputStream out =  s.getOutputStream();
	this.os = new ObjectOutputStream(out);
	InputStream in = s.getInputStream();
	this.is = new ObjectInputStream(in);
	this.accts = a;
	this.kPrivBank = p.getPrivate();
	this.kPubBank = p.getPublic();
	this.crypto = new Crypto();
	this.log = new Log(logFile, this.kPubBank);
	this.session = session;
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
	} catch (Exception e) {
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

	    log.write(new AuthMessage("Waiting for an AuthInit.", session));
	    
	    AuthInit a = (AuthInit) crypto.decryptRSA(nextObject(), kPrivBank);

	    currAcct = accts.getAccount(a.accNumber);
	    atmID = a.atmID;
	    kPubUser = currAcct.getKey();

	    /*
	     *
	     */

	    log.write(new AuthMessage("Got an AuthInit (" + currAcct.getOwner() + " on ATM " +
				      atmID + "), sending challenge.", session));

	    Challenge c = new Challenge(sr.nextInt(), seqNumber++);
	    os.writeObject( crypto.encryptRSA(c, kPubUser) );

	    /*
	     *
	     */

	    Response r = (Response) crypto.decryptRSA(nextObject(), kPrivBank);

	    log.write(new AuthMessage("Received response, checking.", session));

	    if (ProtocolMessage.verify(a, r) == false) {
		return false;
	    } else if (c.nonce != r.nonce) {
		log.write(new AuthMessage("Challenge failed.", session));
		return false;
	    }

	    log.write(new AuthMessage("Challenge passed.", session));

	    /*
	     *
	     */

	    log.write(new AuthMessage("Waiting for challenge.", session));

	    c = (Challenge) crypto.decryptRSA(nextObject(), kPrivBank);

	    if (ProtocolMessage.verify(r, c) == false)
		return false;

	    r = new Response(c.nonce, seqNumber++);

	    os.writeObject( crypto.encryptRSA(r, kPubUser) );

	    log.write(new AuthMessage("Challenge received and answered.", session));

	    /*
	     *
	     */

	    log.write(new AuthMessage("Authenticated, sending session key.", session));

	    kSession = crypto.makeAESKey();
	    os.writeObject( crypto.encryptRSA(kSession, kPubUser) );

	    log.write(new AuthMessage("Initiated session with ACCT#" + currAcct.getNumber() +
				      " on ATM " + atmID + ".", session));

	    return true;

	} catch (IOException e) {
	    e.printStackTrace();
	} catch (ClassNotFoundException e) {
	    e.printStackTrace();
	} catch (KeyException e) {
	    e.printStackTrace();
	} catch (AccountException e) {
	    e.printStackTrace();
	}

	return false;
    }

    // Interacts with an ATMclient to 
    // (1) Perform a transaction 
    // (2) or end transactions if end-of-session message is received
    // (3) Maintain a log of the information exchanged with the client
    public boolean doTransaction() {
	try {

	    SignedMessage m = (SignedMessage) crypto.decryptAES(nextObject(),
								kSession);

	    if (crypto.verify(m.msg, m.signature, kPubUser) == false)
		return false;

	    ProtocolMessage pm = (ProtocolMessage) m.getObject();

	    //if (ProtocolMessage.validate())

	    if (pm instanceof MakeDeposit)
		return doDeposit((MakeDeposit) pm);
	    else if (pm instanceof MakeWithdrawal)
		return doWithdrawal((MakeWithdrawal) pm);
	    else if (pm instanceof CheckBalance)
		return doBalance((CheckBalance) pm);
	    else if (pm instanceof Quit)
		return quit((Quit) pm);

	} catch (IOException e) {
	    e.printStackTrace();
	} catch (ClassNotFoundException e) {
	    e.printStackTrace();
	} catch (KeyException e) {
	    e.printStackTrace();
	} catch (SignatureException e) {
	    e.printStackTrace();
	} catch (TransException e) {
	    e.printStackTrace();
	}

	return false;
    }

    private boolean doWithdrawal(MakeWithdrawal w)
	throws SignatureException, KeyException, IOException, TransException {

	log.write(new TranMessage("Withdraw requested (" + w.withdrawalAmt + ").", session, w));

	currAcct.withdraw(w.withdrawalAmt);

	return doBalance(null);
    }

    private boolean doBalance(CheckBalance b)
	throws SignatureException, KeyException, IOException {

	log.write(new TranMessage("Balance requested.", session, b));

	ProtocolMessage pm = new TransactionResponse(currAcct.getBalance(),
						     seqNumber++);
	Message m = new SignedMessage(pm, kPrivBank, crypto);

	os.writeObject( crypto.encryptAES(m, kSession) );
	
	return true;
    }

    private boolean doDeposit(MakeDeposit d)
	throws SignatureException, KeyException, IOException {

	log.write(new TranMessage("Withdraw requested (" + d.depositAmt + ").", session, d));

	currAcct.deposit(d.depositAmt);
	    
	return doBalance(null);
    }

    private boolean quit(Quit msg) {
	log.write(new TranMessage("Session ended by client.", session, msg));

	accts.save();

	return false;
    }

    private byte[] nextObject() throws IOException, ClassNotFoundException {
	return (byte[]) is.readObject();
    }
}

