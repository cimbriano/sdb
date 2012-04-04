import java.security.*;
import java.lang.management.*;
import java.io.*;
import java.net.*;

public class BankServer {    
    public static final String pubKeyFile = "bank.pub";
    public static final String keyPairFile = "bank.key";
    public static final String logFile = "bank.log";
    private static KeyPair pair = null;
    public static Log log = null;

    static {
	try {
	    pair = (KeyPair)Disk.load(keyPairFile);
	    log = Log.getInstance(pair.getPublic());
	} catch (IOException e) {
	    e.printStackTrace();
	    System.exit(1);
	}
    }

    public static void main(String[] args) {
	String name = ManagementFactory.getRuntimeMXBean().getName();
	int pid = Integer.valueOf(name.substring(0, name.indexOf("@")));

	try {
	    AccountDB accts = AccountDB.load();
	    ServerSocket serverS = new ServerSocket(2105);
	    System.out.println("--------------------------");
	    System.out.println("  Bank Server is Running  ");
	    System.out.println("--------------------------");
	    while (true) {
		try {
		    Socket s = serverS.accept();
		    BankSession session = new BankSession(s, accts, pair, pid++, log);
		    new Thread(session).start();
		} catch (IOException e) {
		    e.printStackTrace();
		}
	    }
	} catch (IOException e) {
	    e.printStackTrace();
	    System.exit(1);
	}
    }
}
