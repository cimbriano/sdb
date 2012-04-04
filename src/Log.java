import java.security.*;
import java.io.*;

import java.text.*;

public class Log implements LogInterface {
    private static final String file = BankServer.logFile;
    private static Crypto crypto;

    // You may add more state here.
    private static PublicKey kPub;
    private static FileOutputStream fos;
    private static ObjectOutputStream oos;
    private static Log instance;

    public Log(PublicKey key) {
	try {
	    this.crypto = new Crypto();
	    this.kPub = key;
	    this.fos = new FileOutputStream(file);
	    this.oos = new ObjectOutputStream(fos);
	} catch (Exception e) {
	    e.printStackTrace();
	    System.exit(1);
	}
    }

    public static synchronized Log getInstance(PublicKey key) {
	if (instance == null)
	    instance = new Log(key);

	return instance;
    }

    public Log() {
	try {
	    this.crypto = new Crypto();
	    this.kPub = null;
	    this.fos = null;
	    this.oos = null;
	} catch (Exception e) {
	    e.printStackTrace();
	    System.exit(1);
	}
    }

    public static synchronized Log getInstance() {
	if (instance == null)
	    instance = new Log();

	return instance;
    }

    public static synchronized void read(PrivateKey key) throws IOException, ClassNotFoundException {
	FileInputStream fis = new FileInputStream(file);
	ObjectInputStream ois = new ObjectInputStream(fis);

	try {
	    while (true) {
		byte[] e = (byte[]) ois.readObject();
		LogMessageHeader h = (LogMessageHeader) crypto.decryptRSA(e, key);
		
		e = (byte[]) ois.readObject();
		LogMessage m = (LogMessage) crypto.decryptAES(e, h.kSession);

		write(m);
	    }
	} catch (KeyException e) {
	    e.printStackTrace();
	} catch (EOFException e) {
	    //EOF -- do nothing, don't throw the exception
	} finally {
	    ois.close();
	    fis.close();
	}	
    }

    public static synchronized void write(LogMessage msg, Key kSession) {
	if (kPub != null && fos != null && oos != null)
	    write((Serializable) msg, kSession);

	write(msg);
    }

    private static void write(LogMessage msg) {
	SimpleDateFormat f = new SimpleDateFormat("MM/dd/yy kk:mm:ss");

	System.out.print("(" + msg.session + ") ");
	System.out.print(f.format(msg.timestamp) + " : ");

	if (msg instanceof AuthMessage)
	    System.out.print("[AUTH]");
	else if (msg instanceof TranMessage)
	    System.out.print("[TRAN]");
	else
	    System.out.print("[    ]");

	System.out.println(" " + msg.message);
    }

    private static void write(Serializable obj, Key kSession) {
	try {
	    LogMessageHeader h = new LogMessageHeader(kSession);

	    byte[] e = crypto.encryptRSA(h, kPub);
	    byte[] o = crypto.encryptAES(obj, kSession);

	    oos.writeObject(e);
	    oos.writeObject(o);	    
	} catch (IOException e) {
	    e.printStackTrace();
	} catch (KeyException e) {
	    e.printStackTrace();
	}
    }

    public static void close() throws IOException {
	oos.close();
	fos.close();
    }
}
