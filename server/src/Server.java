import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.spec.IvParameterSpec;

public class Server {

    public static boolean active = true;
    private static Logger logger = Logger.getLogger("com.instant_messaging.server");

    private static Map<Integer, ClientInfo> clientStore = new HashMap<>();
    private static Map<Integer, String> clientPublicKey = new HashMap<>() {
        {
            put(0, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy0gRSfyb7d8S7KjUYyQhU/c8xO8FU3l5L8em1dtpQDlXWwBzmbgAwjv4DJ0Zv/sDjjfBfGo8mnseSwEQ8kTzi9inWx7YgkSjB38KqsskLngEdtVc1gK9T1BcyZV6rlG8Qte887rx5RdekY0L4CTadlwmVH/kYbF/ClhZryetEbsH6/tcl6vRSuI/GSms5w7hEYmEAMjjD5XO9lW6gHkhg5qB+9J2bB2GIQLEjU+UKquamyTeUQBk4+agQfiqlHOoOC1mp46U6X+yMVY5IktmyNRWWWbPyexmIoS7PVnuWeJ33OyBnNZhdruZ7s3UeBL/YRaSm3LqjQImQYyV8VlI6wIDAQAB");
            put(1, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAteccIEYuNj7bK0jDZbxQWZS2Fb9zoqe3Fv8Wby4WhO7t3wVFo/CMkcpdHYYLb72IX1GhiInRYHty9F5sL7LGGPNXhl8/Eu8221XZcGOBmnv6ztoca3//XTED0or9F+f7A685NQdzFq+xOdE45tlX+Fpjx+PNB5COSZ1lI2CRVruSI1Wr8MVKzorx5J6bUtk/vd6BUmP2qlgmzTrDlcQ0p5i9wkuoUJ7o/mW5WXT7fEoRPRnFvYW84XOM9a62lidQZiuS67+0MINnD3BslK+HhTpKaFZKr0Kkpk6pks0WIjAhgc2nh4ciC+iUTKIACWe+n6L0zbroC/OjRlKrG7nbSQIDAQAB");
            put(2, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0oWXHNpebiYuCVf5kRuG0PK7OnCES6KKoDINr/bbtxxCUuyWekweNlF9kAxTDjU1p85ZKqbuiFYb8xtz/9mhPvoDqVPRJoxs1Bekx/EiUP9jl1JJ10YjUhNGzdUwj/JbBsuY2UrqVRLObiEs7wAAhCKuimGsTZiPHufn75/++qv2YJ0OLp2i30nZX7aAzvE85XbIEK9WLffjBrdUXP5tl2jlmk0ljztiwMruNA7FUB3RBbklElp/6k74gbd9URv0vCWysgnnZL/mtgKOcthHXR8RHH+GaLMF9dCWrZkpy7u0UlvoRRXdWD0pWu/MR9cbBMwCz7SBPDp72txGNAe9CwIDAQAB");
        }
    };

    public static synchronized void storeClientInfo(String clientInfo) throws IOException {

        // Socket sock = socketChannel.socket();
        // InetAddress addr = sock.getInetAddress();
        // int port = sock.getPort();
        // String clientKey = addr.toString() + ":" + Integer.toString(port);
        // clientStore.put(clientInfo., socketChannel);
    }

    public static void main(String[] args) throws Exception {

        clientStore = new HashMap<>();

        logger.log(Level.INFO, "Starting up server...");
        ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.configureBlocking(false);

        serverSocketChannel.bind(new InetSocketAddress("localhost", 7000));
        logger.log(Level.INFO, "Server up and running: " + serverSocketChannel);

        Selector selector = Selector.open();
        serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);

        while (active) {
            int selected = selector.select();
            logger.log(Level.INFO, "Selected: " + selected + " key(s)");

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
        logger.log(Level.INFO, "Server shutting down.");
    }

    private static void accept(Selector selector, SelectionKey key) throws Exception {

        ServerSocketChannel serverSocketChannel = (ServerSocketChannel) key.channel();
        SocketChannel socketChannel = serverSocketChannel.accept();

        if (socketChannel != null) {
            logger.log(Level.INFO, "New connection accepted by server: " + socketChannel);
            socketChannel.configureBlocking(false);
            socketChannel.register(selector, SelectionKey.OP_READ);
        }
    }

    private static void requestHandler(Selector selector, SelectionKey key) throws Exception {
        SocketChannel socketChannel = (SocketChannel) key.channel();

        ByteBuffer buffer = ByteBuffer.allocate(2048);
        int read = socketChannel.read(buffer);
        logger.log(Level.INFO, "Server read '" + read + "' byte(s)");

        buffer.flip();
        byte[] bytes = new byte[buffer.limit()];
        buffer.get(bytes);

        String message = new String(bytes, StandardCharsets.UTF_8);
        logger.log(Level.INFO, "Server received: " + message);

        String[] payload = message.split("\\|");
        if (payload.length == 0) {
            return;
        }

        switch (payload[1]) {
            case "0":
                // String payload = "|0|" + clientID + "|" + randomNumber + "|" +
                // signedRandomNumber + "|" + hostName + "|" + port;
                int clientID = Integer.parseInt(payload[2]);
                String randomNumber = payload[3];
                String signedRandomNumber = payload[4];
                String hostName = payload[5];
                int port = Integer.parseInt(payload[6]);
                if (Crypto.rsaVerify(randomNumber, signedRandomNumber,
                        Crypto.getPublicKey(clientPublicKey.get(clientID)))) {
                    // generate a session key here
                    Key sessionKey = Crypto.generateSessionKey();
                    IvParameterSpec iv = Crypto.generateIv();

                    PublicKey pu = Crypto.getPublicKey(clientPublicKey.get(clientID));

                    // Encrypt the sessionKey with the client's public key
                    String plainText = Base64.getEncoder().encodeToString(sessionKey.getEncoded());
                    System.out.println("Session key: " + plainText);
                    String encryptedSessionKey = Crypto.rsaEncrypt(plainText, pu);
                    // String payload = "|0|" + encryptedSessionKey + "|1|";
                    String response = encryptedSessionKey + "|" + "randomNumberEncrypted";
                    message = Message.getS2CAuthResMsg(response);

                    // TODO: update in-memory client info here
                } else {
                    message = Message.getS2CAuthResMsg("failed");
                }
                break;
            case "1":
                String[] peerIDs = { "" };
                message = Message.getS2CPeerListResMsg(peerIDs);
                break;
            case "2":
                message = Message.getS2CPeerSessionResMsg("clientID1", "clientID2", "sessionKey");
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
        logger.log(Level.INFO, "Server sent: " + message);
        buffer.clear();
    }

}
