import java.io.Serializable;

public class RequestPayload implements Serializable {
	// if type is 0 -> client authenticating itself with the server.
	// if type is 1 -> client requesting the server for info of all clients.
	// if type is 2 -> client requesting the server to issue a session key for
	// secure communication between the client and another peer.
	int messageType;

	// data is the raw bytes that represent the class based on the messageType.
	// For eg: for messageType = 0, data will hold the serialized data of 
	// ClientAuth class. 
	byte[] data;
}
