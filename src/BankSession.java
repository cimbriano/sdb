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

    BankSession(Socket s, AccountDB a, KeyPair p, int session, Log log)
	throws IOException {
	this.s = s;
	OutputStream out =  s.getOutputStream();
	this.os = new ObjectOutputStream(out);
	InputStream in = s.getInputStream();
	this.is = new ObjectInputStream(in);
	this.accts = a;
	this.kPrivBank = p.getPrivate();
	this.kPubBank = p.getPublic();
	this.crypto = new Crypto();
	this.kSession = crypto.makeAESKey();
	this.log = log;
	this.session = session;
	this.prevMsg = null;
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

	    log.write(new AuthMessage("Waiting for an AuthInit.", session), kSession);
	    
	    AuthInit a = (AuthInit) crypto.decryptRSA(nextObject(), kPrivBank);

	    currAcct = accts.getAccount(a.accNumber);
	    atmID = a.atmID;
	    kPubUser = currAcct.getKey();

	    /*
	     *
	     */

	    log.write(new AuthMessage("Got an AuthInit (" + currAcct.getOwner() + " on ATM " + atmID +
				      "), sending challenge.", session), kSession);

	    Challenge c = new Challenge(sr.nextInt(), seqNumber++);
	    os.writeObject( crypto.encryptRSA(c, kPubUser) );

	    /*
	     *
	     */

	    Response r = (Response) crypto.decryptRSA(nextObject(), kPrivBank);

	    log.write(new AuthMessage("Received response, checking.", session), kSession);

	    if (ProtocolMessage.verify(a, r) == false) {
		log.write(new AuthMessage("Out-of-order or stale messages (possible replay attack).", session), kSession);
		return false;
	    } else if (c.nonce != r.nonce) {
		log.write(new AuthMessage("Challenge failed.", session), kSession);
		return false;
	    } else {
		log.write(new AuthMessage("Challenge passed.", session), kSession);
	    }

	    /*
	     *
	     */

	    log.write(new AuthMessage("Waiting for challenge.", session), kSession);

	    c = (Challenge) crypto.decryptRSA(nextObject(), kPrivBank);

	    if (ProtocolMessage.verify(r, c) == false) {
		log.write(new AuthMessage("Out-of-order or stale messages (possible replay attack).", session), kSession);
		return false;
	    }

	    r = new Response(c.nonce, seqNumber++);
	    os.writeObject( crypto.encryptRSA(r, kPubUser) );

	    log.write(new AuthMessage("Challenge received and answered.", session), kSession);

	    prevMsg = c;//save the last message seen from the client

	    /*
	     *
	     */

	    log.write(new AuthMessage("Authenticated, sending session key.", session), kSession);

	    
	    os.writeObject( crypto.encryptRSA(kSession, kPubUser) );

	    log.write(new AuthMessage("Initiated session with ACCT#" + currAcct.getNumber() + " on ATM " + atmID + ".", session),
		      kSession);

	    /*
	     * Send welcome message to client
	     */

	    sendSignedMessage(new TransactionResponse("Welcome " + currAcct.getOwner() + "!", currAcct.getBalance(), seqNumber++));

	    return true;

	} catch (IOException e) {
	    e.printStackTrace();
	} catch (ClassNotFoundException e) {
	    e.printStackTrace();
	} catch (KeyException e) {
	    e.printStackTrace();
	} catch (AccountException e) {
	    e.printStackTrace();
	} catch (SignatureException e) {
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

	    SignedMessage m = (SignedMessage) crypto.decryptAES(nextObject(), kSession);

	    if (crypto.verify(m.msg, m.signature, kPubUser) == false) {
		log.write(new TranMessage("Signature match failed (possible man-in-the-middle attack).", session, m), kSession);
		return false;
	    }

	    ProtocolMessage pm = (ProtocolMessage) m.getObject();

	    if (ProtocolMessage.verify(prevMsg, pm) == false) {
		log.write(new TranMessage("Out-of-order or stale messages (possible replay attack).", session, m), kSession);
		return false;
	    } else {
		prevMsg = pm;
	    }

	    if (pm instanceof MakeDeposit)
		return doDeposit((MakeDeposit) pm, m);
	    else if (pm instanceof MakeWithdrawal)
		return doWithdrawal((MakeWithdrawal) pm, m);
	    else if (pm instanceof CheckBalance)
		return doBalance((CheckBalance) pm, m);
	    else if (pm instanceof Quit)
		return quit((Quit) pm, m);

	} catch (IOException e) {
	    e.printStackTrace();
	} catch (ClassNotFoundException e) {
	    e.printStackTrace();
	} catch (KeyException e) {
	    e.printStackTrace();
	} catch (SignatureException e) {
	    e.printStackTrace();
	}

	return false;
    }

    private boolean doWithdrawal(MakeWithdrawal w, SignedMessage m) throws SignatureException, KeyException, IOException {
	log.write(new TranMessage("Withdraw requested (" + w.withdrawalAmt + ").", session, m), kSession);

	try {
	    currAcct.withdraw(w.withdrawalAmt);
	} catch (TransException e) {	    
	    sendSignedMessage(new TransactionResponse(e.getMessage(), currAcct.getBalance(), seqNumber++));
	    return true;
	}

	return doBalance(null, m);
    }

    private boolean doBalance(CheckBalance b, SignedMessage m) throws SignatureException, KeyException, IOException {
	log.write(new TranMessage("Balance requested.", session, m), kSession);

	sendSignedMessage(new TransactionResponse(currAcct.getBalance(), seqNumber++));
	
	return true;
    }

    private boolean doDeposit(MakeDeposit d, SignedMessage m) throws SignatureException, KeyException, IOException {
	log.write(new TranMessage("Deposit requested (" + d.depositAmt + ").", session, m), kSession);

	currAcct.deposit(d.depositAmt);
	    
	return doBalance(null, m);
    }

    private boolean quit(Quit msg, SignedMessage m) {
	log.write(new TranMessage("Session ended by client.", session, m), kSession);

	accts.save();

	return false;
    }

    private void sendSignedMessage(ProtocolMessage pm)
	throws IOException, KeyException, SignatureException {

	Message m = new SignedMessage(pm, kPrivBank, crypto);
	os.writeObject( crypto.encryptAES(m, kSession) );
    }

    private byte[] nextObject() throws IOException, ClassNotFoundException {
	return (byte[]) is.readObject();
    }
}

