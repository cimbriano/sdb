import java.io.*;

public abstract class ProtocolMessage implements Serializable {
    public int sequenceNumber;
    public long time;

    public ProtocolMessage() {
	time = System.currentTimeMillis();
    }

    private static final int TIME_OUT = 60 * 1000; //1 minute

    public static boolean validate(ProtocolMessage p1, ProtocolMessage p2) {
	long elapse = p2.time - p1.time;

	if (p1.sequenceNumber+1 == p2.sequenceNumber)
	    if (0 <= elapse && elapse < TIME_OUT)
		return true;

	return false;
    }
}