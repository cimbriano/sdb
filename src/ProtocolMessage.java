import java.security.*;
import java.io.*;

public abstract class ProtocolMessage implements Serializable {
    public int sequenceNumber;
    public ProtocolType type;
}