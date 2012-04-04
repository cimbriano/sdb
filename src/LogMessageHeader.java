import java.security.*;
import java.io.*;

public class LogMessageHeader implements Serializable {
    public Key kSession;
    public long salt;
        
    public LogMessageHeader(Key kSession){
	SecureRandom sr = new SecureRandom();
	    
	this.kSession = kSession;
	this.salt = sr.nextLong();
    }        
 }