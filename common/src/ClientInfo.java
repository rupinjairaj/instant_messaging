import java.nio.channels.SocketChannel;

public class ClientInfo {

	public int clientID;
	public String clientPublicKey;
	public boolean status;
	public int incomingPort;
	public String hostName;
	public SocketChannel socketChannel;

	public ClientInfo(int id, String publicKey,
			boolean status, int incomingPort,
			String hostName, SocketChannel socketChannel) {
		this.clientID = id;
	}

}
