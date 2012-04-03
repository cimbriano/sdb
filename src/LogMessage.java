import java.io.*;
import java.util.*;

public abstract class LogMessage implements Serializable {
    public Date timestamp;
    public String message;
    public int session;

    public LogMessage(String message, int session) {
	this.timestamp = new Date();
	this.message = message;
	this.session = session;
    }
}