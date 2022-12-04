import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Server {

    public static boolean active = true;

    private static String hostName;
    private static int port;
    private static int numberOfClients;

    private static PrivateKey serverPrivateKey;
    // store session keys between clients and servers.

    private static Map<Integer, SecretKey> clientSessionKey = new HashMap<>();
    // an in-memory store of a client's public key.
    private static Map<Integer, PublicKey> clientPublicKey = new HashMap<>();

    private static Map<Integer, String> clientHostName = new HashMap<>();
    private static Map<Integer, String> clientPort = new HashMap<>();
    private static Map<Integer, Boolean> clientStatus = new HashMap<>();

    private static void parseArguments(String[] args) {
        /**
         * command line arguments order:
         * localhost 3000
         */
        hostName = args[0];
        port = Integer.parseInt(args[1]);
        numberOfClients = Integer.parseInt(args[2]);
    }

    public static void main(String[] args) throws Exception {

        // parse and setup command line arguments
        parseArguments(args);
        // setup keys in memory
        String serverKeyFilePath = "../keys/server/";
        // String serverKeyFilePath =
        // "/Users/rupinjairaj/projects/utd/sem3/network_security/project/instant_messaging_system/keys/server/";
        serverPrivateKey = Crypto.getPrivateKey(Crypto.readKeyFromFile(serverKeyFilePath + "rsa"));
        for (int i = 0; i < numberOfClients; i++) {
            String clientKeyFilePath = "/Users/rupinjairaj/projects/utd/sem3/network_security/project/instant_messaging_system/keys/client"
                    + i + "/";
            clientPublicKey.put(i, Crypto.getPublicKey(Crypto.readKeyFromFile(clientKeyFilePath + "rsa.pub")));
        }

        // setting up multiplexer
        Selector selector = Selector.open();

        System.out.println("Starting up server...");
        ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.configureBlocking(false);

        serverSocketChannel.bind(new InetSocketAddress(hostName, port));
        System.out.println("Server up and running: " + serverSocketChannel);

        serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);

        while (active) {
            int selected = selector.select(); // blocking
            System.out.println("Selected: " + selected + " key(s)");

            Iterator<SelectionKey> keysIterator = selector.selectedKeys().iterator();
            while (keysIterator.hasNext()) {
                SelectionKey key = keysIterator.next();

                if (key.isAcceptable()) {
                    accept(selector, key);
                }

                if (key.isReadable()) {
                    requestHandler(selector, key);
                }

                if (key.isWritable()) {
                    write(selector, key);
                }

                keysIterator.remove();
            }
        }

        serverSocketChannel.close();
        System.out.println("Server shutting down.");
    }

    private static void accept(Selector selector, SelectionKey key) throws Exception {

        ServerSocketChannel serverSocketChannel = (ServerSocketChannel) key.channel();
        SocketChannel socketChannel = serverSocketChannel.accept();

        if (socketChannel != null) {
            System.out.println("New connection accepted by server: " + socketChannel);
            socketChannel.configureBlocking(false);
            socketChannel.register(selector, SelectionKey.OP_READ);
        }
    }

    private static void requestHandler(Selector selector, SelectionKey key) throws Exception {
        SocketChannel socketChannel = (SocketChannel) key.channel();

        ByteBuffer buffer = ByteBuffer.allocate(2048);
        int read = socketChannel.read(buffer);
        System.out.println("Server read '" + read + "' byte(s)");
        if (read == -1) {
            socketChannel.close();
            return;
        }

        buffer.flip();
        byte[] bytes = new byte[buffer.limit()];
        buffer.get(bytes);

        String message = new String(bytes, StandardCharsets.UTF_8);
        System.out.println("Server received: " + message);

        String[] payload = message.split("\\|");

        int clientID = Integer.parseInt(payload[2]);

        switch (payload[1]) {
            case "0":
                /**
                 * incoming message:
                 * |0|clientID|randomNumber|signedRandomNumber|hostName|port
                 */
                String randomNumber = payload[3];
                String signedRandomNumber = payload[4];
                String hostName = payload[5];
                String port = payload[6];
                // authenticate the client
                if (!Crypto.rsaVerify(randomNumber, signedRandomNumber, clientPublicKey.get(clientID))) {
                    message = Message.getS2CAuthResMsg("failed");
                    break;
                }

                // generate a session key here for client-server communications
                SecretKey sessionKey = Crypto.generateSessionKey();

                PublicKey pu = clientPublicKey.get(clientID);
                // Encrypt the sessionKey with the client's public key
                String base64EncodedSessionKey = Base64.getEncoder().encodeToString(sessionKey.getEncoded());
                System.out.println("Session key: " + base64EncodedSessionKey);
                String encryptedSessionKey = Crypto.rsaEncrypt(base64EncodedSessionKey, pu);
                // server's response:
                // |3|encryptedSessionKey|randomNumberEncrypted|base64IvParameterSpec
                IvParameterSpec iv = Crypto.generateIv();
                String randomNumEncrypted = Crypto.aesEncrypt(randomNumber, iv, sessionKey);
                String base64IvParameterSpec = Base64.getEncoder().encodeToString(iv.getIV());
                String response = encryptedSessionKey + "|" + randomNumEncrypted + "|" + base64IvParameterSpec;
                message = Message.getS2CAuthResMsg(response);
                clientSessionKey.put(clientID, sessionKey);
                clientHostName.put(clientID, hostName);
                clientPort.put(clientID, port);
                clientStatus.put(clientID, true);
                break;
            case "1":
                /**
                 * incoming message:
                 * |1|clientID
                 */
                StringBuilder sb = new StringBuilder();
                for (Integer c_ID : clientStatus.keySet()) {
                    if (clientStatus.get(c_ID)) {
                        sb.append(c_ID + "|");
                    }
                }
                String clientList = sb.toString();
                message = Message.getS2CPeerListResMsg(clientList, clientSessionKey.get(clientID));
                break;
            case "2":
                /**
                 * incoming message:
                 * |2|clientID|encryptedPeerID|IV
                 */
                int sourcePeerID = clientID;
                String encryptedDestPeerID = payload[3];
                String iv_str = payload[4];
                byte[] iv_byte = Base64.getDecoder().decode(iv_str);
                String destPeerIDStr = Crypto.rollingDecrypt(encryptedDestPeerID, new IvParameterSpec(iv_byte),
                        clientSessionKey.get(clientID));
                int destPeerID = Integer.parseInt(destPeerIDStr);
                message = Message.getS2CPeerSessionResMsg(sourcePeerID, destPeerID, clientSessionKey.get(sourcePeerID),
                        clientSessionKey.get(destPeerID), clientPort.get(destPeerID), clientHostName.get(destPeerID));
                break;
            case "10":
                /**
                 * incoming message:
                 * |10|clientID|busy
                 */
                clientStatus.put(clientID, false);
                break;
            default:
                break;
        }
        socketChannel.register(selector, SelectionKey.OP_WRITE, ByteBuffer.wrap(message.getBytes()));
    }

    private static void write(Selector selector, SelectionKey key) throws IOException {
        SocketChannel socketChannel = (SocketChannel) key.channel();
        ByteBuffer buffer = (ByteBuffer) key.attachment();
        socketChannel.write(buffer);

        socketChannel.register(selector, SelectionKey.OP_READ);

        buffer.flip();
        byte[] bytes = new byte[buffer.limit()];
        buffer.get(bytes);

        String message = new String(bytes, StandardCharsets.UTF_8);
        System.out.println("Server sent: " + message);
        buffer.clear();
    }

}
