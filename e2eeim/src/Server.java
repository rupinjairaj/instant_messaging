import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
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

    public static void main(String[] args) {

        // parse and setup command line arguments
        parseArguments(args);
        // setup keys in memory
        for (int i = 0; i < numberOfClients; i++) {
            String clientKeyFilePath = "keys/client" + i + "/";
            clientPublicKey.put(i, Crypto.getPublicKey(Crypto.readKeyFromFile(clientKeyFilePath + "rsa.pub")));
        }

        // setting up multiplexer
        Selector selector;
        try {
            selector = Selector.open();
        } catch (IOException e) {
            System.out.println(e.getMessage());
            return;
        }
        System.out.println("Starting up server...");
        ServerSocketChannel serverSocketChannel;
        try {
            serverSocketChannel = ServerSocketChannel.open();
            serverSocketChannel.configureBlocking(false);
            serverSocketChannel.bind(new InetSocketAddress(hostName, port));
            System.out.println("Server up and running: " + serverSocketChannel);
            serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);
        } catch (IOException e1) {
            System.out.println(e1.getMessage());
        }

        while (active) {
            int selected;
            try {
                selected = selector.select();
                System.out.println("Selected: " + selected + " key(s)");
            } catch (IOException e) {
                System.out.println(e.getMessage());
            } // blocking

            Iterator<SelectionKey> keysIterator = selector.selectedKeys().iterator();
            while (keysIterator.hasNext()) {
                SelectionKey key = keysIterator.next();

                if (key.isValid() && key.isAcceptable()) {
                    accept(selector, key);
                }

                if (key.isValid() && key.isReadable()) {
                    requestHandler(selector, key);
                }

                if (key.isValid() && key.isWritable()) {
                    write(selector, key);
                }
                keysIterator.remove();
            }
        }

        // serverSocketChannel.close();

        System.out.println("Server shutting down.");
    }

    private static void accept(Selector selector, SelectionKey key) {

        ServerSocketChannel serverSocketChannel = (ServerSocketChannel) key.channel();
        SocketChannel socketChannel;
        try {
            socketChannel = serverSocketChannel.accept();
            if (socketChannel != null) {
                System.out.println("New connection accepted by server: " + socketChannel);
                socketChannel.configureBlocking(false);
                socketChannel.register(selector, SelectionKey.OP_READ);
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private static void requestHandler(Selector selector, SelectionKey key) {
        SocketChannel socketChannel = (SocketChannel) key.channel();

        ByteBuffer buffer = ByteBuffer.allocate(2048);
        int read;
        try {
            read = socketChannel.read(buffer);
            System.out.println("Server read '" + read + "' byte(s)");
            if (read == -1) {
                key.cancel();
                socketChannel.close();
                return;
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

        buffer.flip();
        byte[] bytes = new byte[buffer.limit()];
        buffer.get(bytes);

        String message = new String(bytes, StandardCharsets.UTF_8);
        System.out.println("Server received: " + message);

        String[] payload = message.split("\\|");

        int clientID = Integer.parseInt(payload[2]);
        String checkSum;
        String localCheckSum;
        byte[] ivParameterSpecByte;
        String ivParameterSpecString;

        switch (payload[1]) {
            case "0":
                /**
                 * incoming message:
                 * |0|clientID|randomNumber|signedRandomNumber|hostName|port
                 * |0|clientId|randomNumber|signedRandomNumber]hostname|signedHostName|port|signedPort
                 */
                String randomNumber = payload[3];
                String signedRandomNumber = payload[4];
                String hostName = payload[5];
                String signedHostName = payload[6];
                String port = payload[7];
                String signedHostPort = payload[8];
                // If the message has been tampered with in anyway then the RSA verification
                // will fail, thus preserving integrity of the payload.
                if (!Crypto.rsaVerify(randomNumber, signedRandomNumber, clientPublicKey.get(clientID))
                        && !Crypto.rsaVerify(hostName, signedHostName, clientPublicKey.get(clientID))
                        && !Crypto.rsaVerify(port, signedHostPort, clientPublicKey.get(clientID))) {
                    System.out.println("Failed to verify client: " + clientID);
                    return;
                }

                // start building server auth response:
                // |messageTypeCode|encrypted(randomNumber-1)|clientPublicKey(sessionKey)|iv|hash(sessionKey|payload|sessionKey)|
                message = Message.getS2CAuthResMsg(Integer.parseInt(randomNumber), clientPublicKey.get(clientID),
                        clientSessionKey, clientID);
                clientHostName.put(clientID, hostName);
                clientPort.put(clientID, port);
                clientStatus.put(clientID, true);
                try {
                    socketChannel.register(selector, SelectionKey.OP_WRITE, ByteBuffer.wrap(message.getBytes()));
                } catch (ClosedChannelException e) {
                    System.out.println(e.getMessage());
                }
                break;
            case "1":
                /**
                 * incoming message:
                 * |1|clientID
                 */
                StringBuilder sb = new StringBuilder();
                for (Integer c_ID : clientStatus.keySet()) {
                    if (c_ID != clientID && clientStatus.get(c_ID)) {
                        sb.append(c_ID + "|");
                    }
                }
                String clientList = sb.toString();
                // |1|encryptedClientList|iv|hash(sessionKey|payload|sessionKey)
                message = Message.getS2CPeerListResMsg(clientList, clientSessionKey.get(clientID));
                try {
                    socketChannel.register(selector, SelectionKey.OP_WRITE, ByteBuffer.wrap(message.getBytes()));
                } catch (ClosedChannelException e) {
                    System.out.println(e.getMessage());
                }
                break;
            case "2":
                /**
                 * incoming message:
                 * |2|clientId|encryptedPeerId|iv|hash(sessionKey|payload|sessionKey)
                 */
                int sourcePeerID = clientID;
                String encryptedDestPeerID = payload[3];
                ivParameterSpecString = payload[4];
                checkSum = payload[5];
                ivParameterSpecByte = Base64.getDecoder().decode(ivParameterSpecString);
                String destPeerIDStr = Crypto.rollingDecrypt(encryptedDestPeerID,
                        new IvParameterSpec(ivParameterSpecByte),
                        clientSessionKey.get(clientID));
                int destPeerID = Integer.parseInt(destPeerIDStr);
                message = Message.getS2CPeerSessionResMsg(sourcePeerID, destPeerID, clientSessionKey.get(sourcePeerID),
                        clientSessionKey.get(destPeerID), clientPort.get(destPeerID), clientHostName.get(destPeerID),
                        ivParameterSpecString);
                try {
                    socketChannel.register(selector, SelectionKey.OP_WRITE, ByteBuffer.wrap(message.getBytes()));
                } catch (ClosedChannelException e) {
                    System.out.println(e.getMessage());
                }
                break;
            case "5":
                /**
                 * incoming message:
                 * |5|clientId|statusCipher|base64IvParameterSpec|base64EncodedCheckSum
                 */
                // TODO: update client status
                String encryptedStatus = payload[3];
                String base64Iv = payload[4];
                String base64CheckSum = payload[5];
                byte[] ivBytes = Base64.getDecoder().decode(base64Iv);
                String decryptedStatus = Crypto.rollingDecrypt(encryptedStatus, new IvParameterSpec(ivBytes),
                        clientSessionKey.get(clientID));
                // "|5|" + clientId + "|" + String.valueOf(status) + "|" +
                // base64IvParameterSpec;
                // |5|0|v0jW5g==|SUllXEu8NN27TcIz6Urxeg==|cPvjzgCFqgdCcsos8P0ilXMxKvgbHB9z5Fs1f32uQhM=
                System.out.println("Client with ID: " + clientID + " is now " + decryptedStatus);
                // "|5|" + clientId + "|" + statusText + "|" + base64IvParameterSpec;
                String localStatusCheckSumPayload = "|5|" + clientID + "|" + decryptedStatus + "|" + base64Iv;
                byte[] checkSumByte = Crypto.generateCheckSum(clientSessionKey.get(clientID).getEncoded(),
                        localStatusCheckSumPayload.getBytes());
                String localStatusCheckSum = Base64.getEncoder().encodeToString(checkSumByte);
                if (!localStatusCheckSum.equals(base64CheckSum)) {
                    System.out.println("Check sum failed in case 5");
                    return;
                }
                clientStatus.put(clientID, decryptedStatus.equals("idle"));
                break;
            default:
                break;
        }
    }

    private static void write(Selector selector, SelectionKey key) {
        SocketChannel socketChannel = (SocketChannel) key.channel();
        ByteBuffer buffer = (ByteBuffer) key.attachment();
        try {
            socketChannel.write(buffer);
        } catch (IOException e1) {
            System.out.println(e1.getMessage());
        }

        try {
            socketChannel.register(selector, SelectionKey.OP_READ);
        } catch (ClosedChannelException e) {
            System.out.println(e.getMessage());
        }

        buffer.flip();
        byte[] bytes = new byte[buffer.limit()];
        buffer.get(bytes);

        String message = new String(bytes, StandardCharsets.UTF_8);
        System.out.println("Server sent: " + message);
        buffer.clear();
    }

}
