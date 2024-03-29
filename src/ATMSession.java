import java.io.*;
import java.security.*;
import java.net.*;

public class ATMSession implements Session {
    private Socket s;
    private ObjectOutputStream os;
    private ObjectInputStream is;
    private BufferedReader textIn;

    private String ID;
    private ATMCard card;
    private PublicKey kBank;
    private PrivateKey kUser;
    private Crypto crypto;

    // This field is initialized during authentication
    private Key kSession;

    // Additional fields here
    private int seqNumber;
    private ProtocolMessage prevMsg;

    ATMSession(Socket s, String ID, ATMCard card, PublicKey kBank) {
	this.s = s;
	this.ID = ID;
	this.card = card;
	this.kBank = kBank;
	this.crypto = new Crypto();
	try {
	    textIn = new BufferedReader(new InputStreamReader(System.in));
	    OutputStream out =  s.getOutputStream();
	    this.os = new ObjectOutputStream(out);
	    InputStream in = s.getInputStream();
	    this.is = new ObjectInputStream(in);
	} catch (IOException e) {
	    e.printStackTrace();
	}
    }

    // This method authenticates the user and establishes a session key.
    public boolean authenticateUser() {
	System.out.print("Please enter your PIN: ");
	
	// First, the smartcard checks the user's pin to get the 
	// user's private key.
	try {
	    String pin = textIn.readLine();
	    kUser = card.getKey(pin);
	} catch (Exception e) {
	    return false;
	}

	// Implement the client half of the authentication protocol here
	return authenticate();
    }

    private boolean authenticate() {
	SecureRandom sr = new SecureRandom();
	seqNumber = sr.nextInt();

	try {

	    /*
	     * Send the AuthInit.
	     */

	    AuthInit a = new AuthInit(card.getAcctNum(), ID, seqNumber++);
	    os.writeObject( crypto.encryptRSA(a, kBank) );

	    /*
	     * Get the callenge and respond.
	     */

	    Challenge c = (Challenge) crypto.decryptRSA(nextObject(), kUser);
	    Response r = new Response(c.nonce, seqNumber++);
	    os.writeObject( crypto.encryptRSA(r, kBank) );

	    /*
	     * Send the bank a challenge and check it.
	     */

	    c = new Challenge(sr.nextInt(), seqNumber++);	  
	    os.writeObject( crypto.encryptRSA(c, kBank) );

	    r = (Response) crypto.decryptRSA(nextObject(), kUser);

	    if (r.nonce != c.nonce)
		return false;

	    /*
	     * Get the session key and finish authentication.
	     */

	    kSession = (Key) crypto.decryptRSA(nextObject(), kUser);

	    System.out.println("Authenticated! Received session key.");

	    /*
	     * Get the welcome message.
	     */

	    TransactionResponse rsp = readSignedMessage();
	    System.out.println(rsp.message);

	    return true;
	    
	} catch (KeyException e) {
	    e.printStackTrace();
	} catch (IOException e) {
	    e.printStackTrace();
	} catch (ClassNotFoundException e) {
	    e.printStackTrace();
	} catch (SignatureException e) {
	    e.printStackTrace();
	}

	return false;
    }

    void printMenu() {
	System.out.println("*****************************");
	System.out.println("(1) Deposit");
	System.out.println("(2) Withdraw");
	System.out.println("(3) Get Balance");
	System.out.println("(4) Quit\n");
	System.out.print  ("Please enter your selection: ");
    }

    int getSelection() {
	try {
	    String s = textIn.readLine();
	    int i = Integer.parseInt(s, 10);
	    return i;
	} catch (IOException e) {
	    return -1;
	} catch (NumberFormatException e) {
	    return -1;
	}
    }

    double getDouble() {
	try {
	    String s = textIn.readLine();
	    double d = Double.parseDouble(s);
	    return d;
	} catch (IOException e) {
	    return 0.0;
	} catch (NumberFormatException e) {
	    return 0.0;
	}
    }

    void endSession() {
	try {

	    sendSignedMessage(new Quit(seqNumber++));

	} catch (SignatureException e) {
	    e.printStackTrace();
	} catch (KeyException e) {
	    e.printStackTrace();
	} catch (IOException e) {
	    e.printStackTrace();
	} 
    }

    private double getAmount() throws InvalidAmountException {
	double amt = getDouble();

	if (amt <= 0)
	    throw new InvalidAmountException("Invalid amount entered!");
	else
	    return amt;
    }

    private class InvalidAmountException extends Exception {
	public InvalidAmountException(String msg) {
	    super(msg);
	}
    }

    void doDeposit() {
	System.out.print("Enter deposit amount: ");

	try {
	    double amt = getAmount();

	    sendSignedMessage(new MakeDeposit(amt, seqNumber++));
	    TransactionResponse r = readSignedMessage();
		
	    if (r.message == null)
		System.out.println("Deposit complete; new balance = " + r.balance);
	    else
		System.out.println(r.message);
									    
	} catch (SignatureException e) {
	    e.printStackTrace();
	} catch (KeyException e) {
	    e.printStackTrace();
	} catch (IOException e) {
	    e.printStackTrace();
	} catch (ClassNotFoundException e) {
	    e.printStackTrace();
	} catch (InvalidAmountException e) {
	    System.out.println(e.getMessage());
	}
    }

    void doWithdrawal() {
	System.out.print("Enter withdrawal amount: ");

	try {
	    double amt = getAmount();

	    sendSignedMessage(new MakeWithdrawal(amt, seqNumber++));
	    TransactionResponse r = readSignedMessage();

	    if (r.message == null)
		System.out.println("Withdraw complete; new balance = " + r.balance);
	    else
		System.out.println(r.message);

	} catch (SignatureException e) {
	    e.printStackTrace();
	} catch (KeyException e) {
	    e.printStackTrace();
	} catch (IOException e) {
	    e.printStackTrace();
	} catch (ClassNotFoundException e) {
	    e.printStackTrace();
	} catch (InvalidAmountException e) {
	    System.out.println(e.getMessage());
	}	
    }

    void doBalance() {
	try {

	    sendSignedMessage(new CheckBalance(seqNumber++));
	    TransactionResponse r = readSignedMessage();

	    System.out.println("Balance = " + r.balance);

	} catch (SignatureException e) {
	    e.printStackTrace();
	} catch (KeyException e) {
	    e.printStackTrace();
	} catch (IOException e) {
	    e.printStackTrace();
	} catch (ClassNotFoundException e) {
	    e.printStackTrace();
	}
    }

    public boolean doTransaction() {
	printMenu();
	int x = getSelection();
	switch(x) {
	case 1 : doDeposit(); break;
	case 2 : doWithdrawal(); break;
	case 3 : doBalance(); break;
	case 4 : {endSession(); return false;}
	default: {System.out.println("Invalid choice.  Please try again.");}
	}
	return true;
    }

    private TransactionResponse readSignedMessage() throws SignatureException, ClassNotFoundException, IOException, KeyException {
	SignedMessage m = (SignedMessage) crypto.decryptAES(nextObject(), kSession);

	if (crypto.verify(m.msg, m.signature, kBank) == false)
	    throw new SignatureException();

	return (TransactionResponse) m.getObject();
    }

    private void sendSignedMessage(ProtocolMessage pm) throws SignatureException, KeyException, IOException {
	Message m = new SignedMessage(pm, kUser, crypto);
	os.writeObject( crypto.encryptAES(m, kSession) );
    }

    private byte[] nextObject() throws IOException, ClassNotFoundException {
	return (byte[]) is.readObject();
    }
}
