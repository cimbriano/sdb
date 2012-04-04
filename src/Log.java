import java.security.*;
import java.util.*;
import java.text.*;
import java.io.*;

public class Log implements LogInterface {
    private static final String file = BankServer.logFile;
    private static Crypto crypto;

    // You may add more state here.
    private static PublicKey kPub;
    private static Log instance;
    private static List<LogMessageTuple> msgList;

    private static class LogMessageTuple implements Serializable {
	public byte[] header;
	public byte[] message;
    }

    public Log(PublicKey key) {
	try {
	    this.crypto = new Crypto();
	    this.kPub = key;
	    this.msgList = loadList();
	} catch (Exception e) {
	    e.printStackTrace();
	    System.exit(1);
	}
    }

    public static Log getInstance(PublicKey key) {
	if (instance == null)
	    instance = new Log(key);
	return instance;
    }

    public Log() {
	try {
	    this.crypto = new Crypto();
	    this.kPub = null;
	    this.msgList = loadList();
	} catch (Exception e) {
	    e.printStackTrace();
	    System.exit(1);
	}
    }

    public static Log getInstance() {	
	if (instance == null)
	    instance = new Log();
	return instance;
    }

    @SuppressWarnings("unchecked")
    private static List<LogMessageTuple> loadList() throws IOException {
	FileInputStream fis = null;
	ObjectInputStream ois = null;
	Object obj = null;

	try {	
	    fis = new FileInputStream(file);
	    ois = new ObjectInputStream(fis);	    
	    obj = ois.readObject();
	} catch (ClassNotFoundException e) {
	    obj = new ArrayList<LogMessageTuple>();
	} catch (EOFException e) {
	    obj = new ArrayList<LogMessageTuple>();
	} catch (FileNotFoundException e) {
	    obj = new ArrayList<LogMessageTuple>();
	} finally {
	    if (ois != null) ois.close();
	    if (fis != null) fis.close();
	}

	return (List<LogMessageTuple>) obj;	
    }

    private static void saveList() throws FileNotFoundException, IOException {
	FileOutputStream fos = new FileOutputStream(file);
	ObjectOutputStream oos = new ObjectOutputStream(fos);
	oos.writeObject(msgList);
	oos.close();
	fos.close();
    }

    public static void read(PrivateKey key) throws IOException, ClassNotFoundException {
	try {
	    for (LogMessageTuple t : msgList) {
		LogMessageHeader h = (LogMessageHeader) crypto.decryptRSA(t.header, key);
		LogMessage m = (LogMessage) crypto.decryptAES(t.message, h.kSession);

		write(m);
	    }
	} catch (KeyException e) {
	    e.printStackTrace();
	}
    }

    public static synchronized void write(LogMessage msg, Key kSession) {
	if (kPub != null)
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
	    LogMessageTuple t = new LogMessageTuple();
	    LogMessageHeader h = new LogMessageHeader(kSession);

	    t.header = crypto.encryptRSA(h, kPub);
	    t.message = crypto.encryptAES(obj, kSession);

	    msgList.add(t);
	    saveList();
	} catch (KeyException e) {
	    e.printStackTrace();
	} catch (FileNotFoundException e) {
	    e.printStackTrace();
	} catch (IOException e) {
	    e.printStackTrace();
	}
    }
}
