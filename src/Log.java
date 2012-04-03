import java.security.PublicKey;
import java.security.Key;
import java.io.IOException;
import java.io.Serializable;

import java.text.*;

public class Log implements LogInterface {

    private String file;
    private Crypto crypto;

    // You may add more state here.

    public Log(String file, PublicKey key) 
    {
	try {
	    this.crypto = new Crypto();
	    this.file = file;

	    // Initialize the log file
	    // ...

	} catch (Exception e) {
	    e.printStackTrace();
	    System.exit(1);
	}
    }

    public void write(LogMessage msg) {
	SimpleDateFormat f = new SimpleDateFormat("MM/dd/yy kk:mm:ss");

	System.out.print("(" + msg.session + ") ");
	System.out.print(f.format(msg.timestamp) + " : ");

	if (msg.type == LogMessage.Type.AUTH)
	    System.out.print("[AUTH]");
	else if (msg.type == LogMessage.Type.TRANSACTION)
	    System.out.print("[TRAN]");
	else
	    System.out.print("[    ]");

	System.out.println(" " + msg.message);

	write( (Serializable) msg );
    }

    public void write(Serializable obj) {
	try {
	    Disk.append(obj, file);
	} catch (IOException e) {
	    e.printStackTrace();
	}
    }

}
