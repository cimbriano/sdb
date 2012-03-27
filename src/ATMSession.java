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
	System.out.println("Please enter your PIN: ");
	
	// First, the smartcard checks the user's pin to get the 
	// user's private key.
	try {
	    String pin = textIn.readLine();
	    kUser = card.getKey(pin);
	} catch (Exception e) {
	    return false;
	}

	// Implement the client half of the authentication protocol here
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
    }

    void doDeposit() {
    }

    void doWithdrawal() {
    }

    void doBalance() {
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
}
