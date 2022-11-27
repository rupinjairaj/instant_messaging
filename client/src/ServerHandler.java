import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ServerHandler {
	private static Logger logger = Logger.getLogger("com.instant_messaging.client.server_handler");

	public SocketChannel serverSocketChannel;

	public boolean establishConnection(String address, int port) {

		try {
			serverSocketChannel = SocketChannel.open(new InetSocketAddress(address, port));
			serverSocketChannel.configureBlocking(false);
			logger.log(Level.INFO, "Connection established with the server.");
			return true;
		} catch (IOException e) {
			logger.log(Level.SEVERE,
					"An error occurred while establishing the SocketChannel to the server " + e.getMessage());
			return false;
		}

	}

	public boolean sendAuthMessage(String authMessage) {
		
		try {
			ByteBuffer buffer = ByteBuffer.wrap(authMessage.getBytes());
			serverSocketChannel.write(buffer);
			logger.log(Level.INFO, "Client sent auth message to server");
			return true;
		} catch (IOException e) {
			logger.log(Level.SEVERE, "An error occurred sending the auth message to the server " + e.getMessage());
		}
		return false;

	}

}
