import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.sql.Timestamp;
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
	private String peerHostName;
	private int peerHostPort;
	private int clientServerCurrSecureRandomNumber;
	private long p2pTime;

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

		clientServerCurrSecureRandomNumber = random.nextInt();

		String sessionKeyReqPayload = Message.getC2SAuthMsg(this.clientID, this.clientHostName, this.clientPort,
				clientServerCurrSecureRandomNumber, clientPrivateKey);
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
			case "0":
				/**
				 * incoming message:
				 * |messageTypeCode|encrypted(randomNumber-1)|clientPublicKey(sessionKey)|iv|hash(sessionKey|payload|sessionKey)|
				 */
				String encryptedRandomNumberMinus1 = payload[2];
				String encryptedSessionKey = payload[3];
				String base64IvParameterSpec = payload[4];
				String base64EncodedCheckSum = payload[5];

				String sessionKey = Crypto.rsaDecrypt(encryptedSessionKey, clientPrivateKey);

				byte[] ivParameterSpecBytes = Base64.getDecoder().decode(base64IvParameterSpec);

				byte[] clientServerKeyBytes = Base64.getDecoder().decode(sessionKey);
				// saving the client-server session key in-memory
				clientServerSecretKey = new SecretKeySpec(clientServerKeyBytes, 0, clientServerKeyBytes.length, "AES");
				// decrypt the encryptedRandomNumber (check for freshness of the session key)
				String decryptedRandomNumber = Crypto.aesDecrypt(encryptedRandomNumberMinus1,
						new IvParameterSpec(ivParameterSpecBytes), clientServerSecretKey);
				if (Integer.parseInt(decryptedRandomNumber) != clientServerCurrSecureRandomNumber - 1) {
					return;
				}
				String responsePayload = "|0|" + encryptedRandomNumberMinus1 + "|" + encryptedSessionKey + "|"
						+ base64IvParameterSpec;
				byte[] checkSum = Crypto.generateCheckSum(clientServerSecretKey.getEncoded(),
						responsePayload.getBytes());
				String checkSumForVerification = Base64.getEncoder().encodeToString(checkSum);
				if (!checkSumForVerification.equals(base64EncodedCheckSum)) {
					return;
				}

				// setting up the client's incoming connection handler thread
				IncomingConnectionHandler peerListener = new IncomingConnectionHandler(clientID, clientHostName,
						clientPort,
						clientServerSecretKey, clientServerSocketChannel);
				Thread listenerThread = new Thread(peerListener, "th_peerListener");
				listenerThread.start();
				System.out.println(
						"Session key obtained: " + sessionKey + " decrypted random number: " + decryptedRandomNumber);
				break;
			case "1":
				/**
				 * incoming message:
				 * |1|encryptedClientList|iv|hash(sessionKey|payload|sessionKey)
				 */
				String cipherPeerListText = payload[2];
				String iv = payload[3];
				String base64EncodedClientListResponseCheckSum = payload[4];
				byte[] ivByte = Base64.getDecoder().decode(iv);
				String plainTextPeerList = Crypto.rollingDecrypt(cipherPeerListText, new IvParameterSpec(ivByte),
						clientServerSecretKey);
				String resPayload = "|1|" + cipherPeerListText + "|" + iv;
				byte[] verifyClientListResponseCheckSumByte = Crypto.generateCheckSum(
						clientServerSecretKey.getEncoded(),
						resPayload.getBytes());
				String verifyClientListResponseCheckSumString = Base64.getEncoder()
						.encodeToString(verifyClientListResponseCheckSumByte);
				if (!verifyClientListResponseCheckSumString.equals(base64EncodedClientListResponseCheckSum)) {
					return;
				}
				String[] peerList = plainTextPeerList.split("\\|");
				System.out.println("Here are the list of available peers:");
				for (String peer : peerList) {
					System.out.print(peer + " ");
				}
				System.out.println();
				System.out.println("Please press the ID of the peer you wish to chat with:");
				// get user input here
				String selectedPeerID = waitAndHandleUserInput();
				// |2|clientId|encryptedPeerId|iv|hash(sessionKey|payload|sessionKey)
				message = Message.getC2SPeerSessionReqMsg(clientID, selectedPeerID, clientServerSecretKey);
				this.registerWithMultiplexer(socketChannel, selector, SelectionKey.OP_WRITE,
						ByteBuffer.wrap(message.getBytes()));
				break;
			case "2":
				/**
				 * incoming message:
				 * |2|sourceClientEncrypt(incomingIv|destPeerId|destHostName|destHostPort|p2pSessionKey|destPeerTicket|destIv)|sourceIv|hash(sessionKey|payload|sessionKey)|
				 * destPeerTicket -
				 * destClientEncrypt(p2pSessionKey|sourcePeerId|expirationTime)
				 */
				String cipherText = payload[2];
				String newIv = payload[3];
				String newChecksum = payload[4];
				byte[] newIvByte = Base64.getDecoder().decode(newIv);
				// incomingIv|destPeerId|destHostName|destHostPort|p2pSessionKey|destPeerTicket|destIv
				String plainText = Crypto.rollingDecrypt(cipherText, new IvParameterSpec(newIvByte),
						clientServerSecretKey);
				byte[] verifyCheckSumByte = Crypto.generateCheckSum(clientServerSecretKey.getEncoded(),
						plainText.getBytes());
				String verifyCheckSum = Base64.getEncoder().encodeToString(verifyCheckSumByte);
				if (!verifyCheckSum.equals(newChecksum)) {
					System.out.println("message has been tampered with.");
					return;
				}
				String[] plainTextList = plainText.split("\\|");
				peerClientId = Integer.parseInt(plainTextList[1]);
				peerHostName = plainTextList[2];
				peerHostPort = Integer.parseInt(plainTextList[3]);
				String peerToPeerSessionKey = plainTextList[4];
				byte[] peerToPeerSessionKeyBytes = Base64.getDecoder().decode(peerToPeerSessionKey);
				peerToPeerSecretKey = new SecretKeySpec(peerToPeerSessionKeyBytes, 0, peerToPeerSessionKeyBytes.length,
						"AES");
				String destPeerTicket = plainTextList[5];
				String destPeerIv = plainTextList[6];
				// connect with the peer
				try {
					peerToPeerSocketChannel = SocketChannel.open(new InetSocketAddress(peerHostName, peerHostPort));
					peerToPeerSocketChannel.configureBlocking(false);
				} catch (IOException e) {
					System.out.println(e.getMessage());
				}
				// send the session key payload
				// |2|clientID|ticketForPeer|iv|p2pSessionKeyEncrypted(timestamp)|timeEncIv
				Timestamp timestamp = new Timestamp(System.currentTimeMillis());
				p2pTime = timestamp.toInstant().toEpochMilli();
				message = Message.getP2PSessionMsg(destPeerTicket, destPeerIv, peerToPeerSecretKey, p2pTime);
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
			case "3":
				/**
				 * incoming message:
				 * |3|p2pSessionKeyEncrypt(originalChallenge+1)|iv
				 */
				String challengeIv = payload[3];
				byte[] challengeIvByte = Base64.getDecoder().decode(challengeIv);
				String decryptedChallengeTime = Crypto.aesDecrypt(payload[2], new IvParameterSpec(challengeIvByte),
						peerToPeerSecretKey);
				if (p2pTime + 1 != Long.parseLong(decryptedChallengeTime)) {
					return;
				}

				// Tell the server you are busy
				// |5|clientId|encrypted(status)|iv|hash(sessionKey|payload|sessionKey)
				message = Message.getC2SStatusUpdateMsg(clientID, false, clientServerSecretKey);
				this.registerWithMultiplexer(clientServerSocketChannel, selector, SelectionKey.OP_WRITE,
						ByteBuffer.wrap(message.getBytes()));

				// first chat message to peer
				System.out.println("Enter your message: ");
				String plainChatText = waitAndHandleUserInput();
				// |4|encChatMsg|iv|checkSum
				message = Message.getP2PChatMsg(plainChatText, peerToPeerSecretKey);
				this.registerWithMultiplexer(socketChannel, selector, SelectionKey.OP_WRITE,
						ByteBuffer.wrap(message.getBytes()));
				break;
			case "4":
				/**
				 * incoming message:
				 * |4|encChatMsg|iv|checkSum
				 */
				String encChat = payload[2];
				String base64Iv = payload[3];
				String chatCheckSum = payload[4];
				byte[] base64IvByte = Base64.getDecoder().decode(base64Iv);
				String chatText = Crypto.rollingDecrypt(encChat, new IvParameterSpec(base64IvByte),
						peerToPeerSecretKey);
				byte[] checkSumByte = Crypto.generateCheckSum(peerToPeerSecretKey.getEncoded(), chatText.getBytes());
				String checkSumStr = Base64.getEncoder().encodeToString(checkSumByte);
				if (!chatCheckSum.equals(checkSumStr)) {
					System.out.println("the message has been tampered with.");
					return;
				}
				System.out.println("Peer@" + peerClientId + ": " + chatText);
				System.out.println("Enter your message: ");
				chatText = waitAndHandleUserInput();
				// |4|encChatMsg|iv|checkSum
				message = Message.getP2PChatMsg(chatText, peerToPeerSecretKey);
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