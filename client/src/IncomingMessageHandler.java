import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Iterator;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class IncomingMessageHandler implements Runnable {

	private PrivateKey clientPrivateKey;
	private PublicKey clientPublicKey;
	private SecretKey clientServerSecretKey;
	private SecretKey peerToPeerSecretKey;
	private int peerClientId;

	private int clientID;
	private String serverHostName;
	private int serverPort;
	String clientHostName;
	int clientPort;
	private boolean clientStatus = true; // True - available, False - busy

	private SocketChannel clientServerSocketChannel;
	private SocketChannel peerToPeerSocketChannel;

	public IncomingMessageHandler(PrivateKey clientPrivateKey, PublicKey clientPublicKey,
			int clientID, String clientHostName, int clientPort,
			String serverHostName, int serverPort) {
		this.clientID = clientID;
		this.clientPrivateKey = clientPrivateKey;
		this.clientPublicKey = clientPublicKey;
		this.serverHostName = serverHostName;
		this.serverPort = serverPort;
		this.clientHostName = clientHostName;
		this.clientPort = clientPort;
	}

	@Override
	public void run() {

		// setting up multiplexer
		Selector selector;
		try {
			selector = Selector.open();
		} catch (IOException e) {
			System.out.println(e.getMessage());
			return;
		}

		SecureRandom random = new SecureRandom();

		// connect with the server
		try {
			clientServerSocketChannel = SocketChannel.open(new InetSocketAddress(serverHostName, serverPort));
			clientServerSocketChannel.configureBlocking(false);
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}
		System.out.println("Connection established with the server.");

		try {
			clientServerSocketChannel.register(selector, SelectionKey.OP_READ);
		} catch (ClosedChannelException e) {
			System.out.println(e.getMessage());
		}

		int ranNum = random.nextInt();
		String ranNumSign = Crypto.rsaSign(String.valueOf(ranNum), clientPrivateKey);

		String sessionKeyReqPayload = Message.getC2SAuthMsg(this.clientID,
				this.clientHostName, this.clientPort, ranNum,
				ranNumSign);
		try {
			clientServerSocketChannel.write(ByteBuffer.wrap(sessionKeyReqPayload.getBytes()));
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}

		while (true) {
			int selected;
			try {
				selected = selector.select();
			} catch (IOException e) {
				System.out.println(e.getMessage());
				continue;
			}
			System.out.println("Selected: " + selected + " key(s)");

			Iterator<SelectionKey> keysIterator = selector.selectedKeys().iterator();
			while (keysIterator.hasNext()) {
				SelectionKey key = keysIterator.next();

				// if (key.isAcceptable()) {
				// this.accept(selector, key);
				// }

				if (key.isReadable()) {
					this.requestHandler(selector, key);
				}

				if (key.isWritable()) {
					this.write(selector, key);
				}

				keysIterator.remove();
			}

			// use user input here to do operations like request server for
			// info of all clients, connect with a specific client from the
			// list of clients returened by the server and chat with the
			// client.
			if (!clientStatus) {
				continue;
			}
			System.out.println("Press 1 to get available client list\nPress 2 to wait for incoming connections");
			int optionSelected = Integer.parseInt(this.waitAndHandleUserInput());
			if (optionSelected == 1) {
				clientStatus = false;
				String message = Message.getC2SPeerListReqMsg(clientID);
				this.registerWithMultiplexer(clientServerSocketChannel, selector, SelectionKey.OP_WRITE,
						ByteBuffer.wrap(message.getBytes()));
			} else if (optionSelected == 2) {
				try {
					synchronized (this) {
						wait();
					}
				} catch (InterruptedException e) {
					System.out.println(e.getMessage());
				}

			}
		}

	}

	// private void accept(Selector selector, SelectionKey key) {
	// ServerSocketChannel serverSocketChannel = (ServerSocketChannel)
	// key.channel();
	// SocketChannel socketChannel;
	// try {
	// socketChannel = serverSocketChannel.accept();
	// } catch (IOException e) {
	// System.out.println(e.getMessage());
	// return;
	// }
	// if (socketChannel != null) {
	// System.out.println("New connection accepted by client.");
	// this.registerWithMultiplexer(socketChannel, selector, SelectionKey.OP_READ,
	// null);
	// }
	// }

	private void requestHandler(Selector selector, SelectionKey key) {

		SocketChannel socketChannel = (SocketChannel) key.channel();

		ByteBuffer buffer = ByteBuffer.allocate(1024);

		try {
			int read = socketChannel.read(buffer);
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}

		buffer.flip();
		byte[] bytes = new byte[buffer.limit()];
		buffer.get(bytes);

		String message = new String(bytes, StandardCharsets.UTF_8);
		System.out.println("Client reveived: " + message);
		String[] payload = message.split("\\|");

		switch (payload[1]) {
			case "3":
				// incoming message:
				// |3|encryptedSessionKey|randomNumberEncrypted|base64IvParameterSpec
				String encryptedSessionKey = payload[2];
				if (encryptedSessionKey.equals("failed")) {
					System.out.println("The server failed to authenticate the client");
					break;
				}
				String encryptedRandomNumber = payload[3];
				String base64IvParameterSpec = payload[4];
				String sessionKey = Crypto.rsaDecrypt(encryptedSessionKey, clientPrivateKey);
				byte[] clientServerKeyBytes = Base64.getDecoder().decode(sessionKey);
				byte[] ivParameterSpecBytes = Base64.getDecoder().decode(base64IvParameterSpec);
				// saving the client-server session key in-memory
				clientServerSecretKey = new SecretKeySpec(clientServerKeyBytes, 0, clientServerKeyBytes.length, "AES");
				// decrypt the encryptedRandomNumber (check for freshness of the session key)
				String decryptedRandomNumber = Crypto.aesDecrypt(encryptedRandomNumber,
						new IvParameterSpec(ivParameterSpecBytes), clientServerSecretKey);
				System.out.println(
						"Session key obtained: " + sessionKey + " decrypted random number: " + decryptedRandomNumber);
				break;
			case "4":
				/**
				 * incoming message:
				 * |4|peerIdCipherText|IV
				 */
				String cipherPeerListText = payload[2];
				String iv = payload[3];
				byte[] iv_byte = Base64.getDecoder().decode(iv);
				String plainTextPeerList = Crypto.rollingDecrypt(cipherPeerListText, new IvParameterSpec(iv_byte),
						clientServerSecretKey);

				String[] peerList = plainTextPeerList.split("\\|");
				System.out.println("Here are the list of available peers:");
				for (String peer : peerList) {
					System.out.print(peer + " ");
				}
				System.out.println();
				System.out.println("Please press the ID of the peer you wish to chat with:");
				// get user input here
				String selectedPeerID = waitAndHandleUserInput();
				message = Message.getC2SPeerSessionReqMsg(clientID, selectedPeerID, clientServerSecretKey);
				this.registerWithMultiplexer(socketChannel, selector, SelectionKey.OP_WRITE,
						ByteBuffer.wrap(message.getBytes()));
				break;
			case "5":
				/**
				 * incoming message:
				 * |5|clientID1|clientID2|base64EncodedSessionKey|desClientPort|destClientHostName
				 */
				peerClientId = Integer.parseInt(payload[3]);
				String encryptedPeerSessionKey = payload[4];
				int peerPort = Integer.parseInt(payload[5]);
				String peerHostName = payload[6];
				// connect with the peer
				try {
					peerToPeerSocketChannel = SocketChannel.open(new InetSocketAddress(peerHostName, peerPort));
					peerToPeerSocketChannel.configureBlocking(false);
				} catch (IOException e) {
					System.out.println(e.getMessage());
				}
				// send the session key payload
				// TODO: extract the ticket for the peer and send it over
				String ticketForPeer = encryptedPeerSessionKey;
				message = Message.getP2PSessionMsg(clientID, ticketForPeer);
				this.registerWithMultiplexer(peerToPeerSocketChannel, selector, SelectionKey.OP_WRITE,
						ByteBuffer.wrap(message.getBytes()));
				break;
			// case "6":
			// /**
			// * incoming message:
			// * |6|clientID|ticketForPeer
			// */
			// String ticketForClient = payload[3];
			// System.out.println("Client received p2p session key: " + ticketForClient);
			// byte[] peerToPeerSecretKeyBytes =
			// Base64.getDecoder().decode(ticketForClient);
			// // saving the client-server session key in-memory
			// peerToPeerSecretKey = new SecretKeySpec(peerToPeerSecretKeyBytes, 0,
			// peerToPeerSecretKeyBytes.length,
			// "AES");
			// break;
			case "7":
				/**
				 * incoming message:
				 * |6|aNewChallenge|responseToChallenge|dataFromTicketForServer
				 */
				message = "|8|responseToANewChallenge";
				this.registerWithMultiplexer(socketChannel, selector, SelectionKey.OP_WRITE,
						ByteBuffer.wrap(message.getBytes()));
				message = "|10|" + clientID + "|busy";
				this.registerWithMultiplexer(clientServerSocketChannel, selector, SelectionKey.OP_WRITE,
						ByteBuffer.wrap(message.getBytes()));
				break;
			case "8":
				/**
				 * incoming message:
				 * |8|sessionEstablished
				 */
				System.out.println("Peer@" + peerClientId + ": " + payload[2]);
				System.out.println("Enter your message: ");
				message = "|9|" + waitAndHandleUserInput();
				this.registerWithMultiplexer(socketChannel, selector, SelectionKey.OP_WRITE,
						ByteBuffer.wrap(message.getBytes()));
			default:
				break;
		}
	}

	private void registerWithMultiplexer(SocketChannel socketChannel, Selector selector, int selectionKey,
			ByteBuffer payload) {
		try {
			if (selectionKey == SelectionKey.OP_READ) {
				socketChannel.configureBlocking(false);
			}
			if (selectionKey == SelectionKey.OP_WRITE) {
				socketChannel.register(selector, selectionKey, payload);
				return;
			}
			socketChannel.register(selector, selectionKey);
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}

	private String waitAndHandleUserInput() {
		String input = "";
		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		try {
			input = reader.readLine();
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}
		return input;
	}

	public void write(Selector selector, SelectionKey key) {
		SocketChannel socketChannel = (SocketChannel) key.channel();
		ByteBuffer buffer = (ByteBuffer) key.attachment();
		try {
			socketChannel.write(buffer);
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}
		this.registerWithMultiplexer(socketChannel, selector, SelectionKey.OP_READ, null);
	}

}