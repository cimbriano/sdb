import java.security.*;
import java.io.IOException;
import java.io.Serializable;

import java.text.*;

public class Log implements LogInterface {

    private String file;
    private Crypto crypto;

    // You may add more state here.
    private PublicKey kPub;
    private Key aesSessionKey;

    public Log(String file, PublicKey key, Key sessionKey) {
	try {
	    this.crypto = new Crypto();
	    this.file = file;
	    this.kPub = key;
	    this.aesSessionKey = sessionKey;
	} catch (Exception e) {
	    e.printStackTrace();
	    System.exit(1);
	}
    }

    public void write(LogMessage msg) {
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

	write( (Serializable) msg );
    }

    public void write(Serializable obj) {
	try {
	    byte[] e = crypto.encryptRSA(new LogMessageHeader(aesSessionKey), kPub);
	    byte[] o = crypto.encryptAES(obj, aesSessionKey);

	    Disk.append(e, file);
	    Disk.append(o, file);
	    
	} catch (IOException e) {
	    e.printStackTrace();
	} catch (KeyException e) {
	    e.printStackTrace();
	}
    }
    
    private class LogMessageHeader implements Serializable {
        private Key sessionKey;
        private long salt;
        
        public LogMessageHeader(Key sessionKey){
                SecureRandom sr = new SecureRandom();
        
                this.sessionKey = sessionKey;
                salt = sr.nextLong();
        }
        
    }

}
