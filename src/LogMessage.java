import java.io.*;
import java.util.*;

public class LogMessage implements Serializable {
    public Type type;
    public Date timestamp;
    public String message;
    //public Priority priority;
    public int session;
    public ProtocolMessage pm;

    public LogMessage(Type type, String message, int session) {
	this.timestamp = new Date();
	this.message = message;
	this.type = type;
	this.session = session;
    }

    /*public LogMessage(Type type, String message, int session, Priority priority) {
	this.timestamp = new Date();
	this.message = message;
	this.type = type;
	this.session = session;
	this.priority = priority;
	}*/

    public enum Type {
	AUTH, TRANSACTION
    }

    public enum Priority {
	DEFAULT, LOW, MED, HIGH
    }
}