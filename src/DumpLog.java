import java.security.*;
import java.io.*;

public class DumpLog {
    private static KeyPair pair;

    static {
	try {
	    pair = (KeyPair) Disk.load(BankServer.keyPairFile);
	} catch (IOException e) {
	    e.printStackTrace();
	    System.exit(1);
	}
    }	

    public static void main(String args[]) {
	Log log = new Log();

	try {
	    log.read(pair.getPrivate());
	} catch (IOException e) {
	    e.printStackTrace();
	} catch (ClassNotFoundException e) {
	    e.printStackTrace();
	}
    }
}