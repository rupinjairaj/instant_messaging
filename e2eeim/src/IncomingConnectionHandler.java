import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.Iterator;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class IncomingConnectionHandler implements Runnable {

    private ServerSocketChannel clientServerSocketChannel;
    private SocketChannel clientToServerSocketChannel;
    private String hostName;
    private int port;
    private int clientId;
    private SecretKey peerToPeerSecretKey;
    private SecretKey clientServerSecretKey;
    private int peerClientId;

    public IncomingConnectionHandler(int clientId, String hostName, int port, SecretKey clientServerSecretKey,
            SocketChannel clientToServerSocketChannel) {
        this.clientId = clientId;
        this.hostName = hostName;
        this.port = port;
        this.clientServerSecretKey = clientServerSecretKey;
        this.clientToServerSocketChannel = clientToServerSocketChannel;
    }

    @Override
    public void run() {
        try (Selector localSelector = Selector.open()) {
            System.out.println("Setting up client's server...");
            this.clientServerSocketChannel = ServerSocketChannel.open();
            this.clientServerSocketChannel.configureBlocking(false);
            this.clientServerSocketChannel.bind(new InetSocketAddress(this.hostName, this.port));
            this.clientServerSocketChannel.register(localSelector, SelectionKey.OP_ACCEPT);
            System.out.println("Client's server socket is up and waiting for connections...");
            while (true) {
                int selected = localSelector.select();
                System.out.println("Local selector selected: " + selected + " key(s)");
                Iterator<SelectionKey> keysIterator = localSelector.selectedKeys().iterator();
                while (keysIterator.hasNext()) {
                    SelectionKey key = keysIterator.next();
                    if (key.isAcceptable()) {
                        accept(localSelector, key);
                    }

                    if (key.isReadable()) {
                        requestHandler(localSelector, key);
                    }
                    if (key.isWritable()) {
                        write(localSelector, key);
                    }
                    keysIterator.remove();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void write(Selector localSelector, SelectionKey key) throws Exception {
        SocketChannel socketChannel = (SocketChannel) key.channel();
        ByteBuffer buffer = (ByteBuffer) key.attachment();
        socketChannel.write(buffer);
        socketChannel.register(localSelector, SelectionKey.OP_READ);
    }

    private void requestHandler(Selector localSelector, SelectionKey key) throws Exception {
        SocketChannel socketChannel = (SocketChannel) key.channel();

        ByteBuffer buffer = ByteBuffer.allocate(1024);
        int read = socketChannel.read(buffer);
        if (read == -1) {
            socketChannel.close();
            return;
        }

        buffer.flip();
        byte[] bytes = new byte[buffer.limit()];
        buffer.get(bytes);

        String message = new String(bytes, StandardCharsets.UTF_8);
        System.out.println("Client reveived: " + message);
        String[] payload = message.split("\\|");

        switch (payload[1]) {
            case "2":
                /**
                 * incoming message:
                 * |2|ticketForPeer|iv|p2pSessionKeyEncrypted(timestamp)|timeEncIv
                 */
                String encryptedTicket = payload[2];
                String ticketIv = payload[3];
                byte[] ticketIvByte = Base64.getDecoder().decode(ticketIv);
                System.out.println("Client received p2p session key: " + encryptedTicket);
                String decryptedTicket = Crypto.rollingDecrypt(encryptedTicket, new IvParameterSpec(ticketIvByte),
                        clientServerSecretKey);
                // ticket - p2pSessionKey|sourcePeerId|expirationTime
                String[] decryptedTicketList = decryptedTicket.split("\\|");
                String base64EncodedP2PSessionKey = decryptedTicketList[0];
                peerClientId = Integer.parseInt(decryptedTicketList[1]);
                long expirationTime = Long.parseLong(decryptedTicketList[2]);
                Timestamp timestamp = new Timestamp(System.currentTimeMillis());
                Instant instant = timestamp.toInstant();
                if (instant.toEpochMilli() > expirationTime) {
                    return;
                }
                byte[] peerToPeerSecretKeyBytes = Base64.getDecoder().decode(base64EncodedP2PSessionKey);
                // saving the client-server session key in-memory
                this.peerToPeerSecretKey = new SecretKeySpec(peerToPeerSecretKeyBytes, 0,
                        peerToPeerSecretKeyBytes.length,
                        "AES");
                String p2pTimeEncrypted = payload[4];
                String base64TimeIv = payload[5];
                byte[] timeIvByte = Base64.getDecoder().decode(base64TimeIv);
                String decryptedTime = Crypto.aesDecrypt(p2pTimeEncrypted, new IvParameterSpec(timeIvByte),
                        peerToPeerSecretKey);
                long p2pTime = Long.valueOf(decryptedTime);
                // |3|p2pSessionKeyEncrypt(originalChallenge+1)|iv
                message = Message.getP2PChallengeResMsg(p2pTime + 1, peerToPeerSecretKey);
                socketChannel.register(localSelector, SelectionKey.OP_WRITE, ByteBuffer.wrap(message.getBytes()));

                // Tell the server you are busy
                // |5|clientId|encrypted(status)|iv|hash(sessionKey|payload|sessionKey)
                message = Message.getC2SStatusUpdateMsg(clientId, false, clientServerSecretKey);
                clientToServerSocketChannel.write(ByteBuffer.wrap(message.getBytes()));
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
                String checkSum = Base64.getEncoder().encodeToString(checkSumByte);
                if (!chatCheckSum.equals(checkSum)) {
                    System.out.println("the message has been tampered with.");
                    return;
                }
                System.out.println("Peer@" + peerClientId + ": " + chatText);
                System.out.println("Enter your message: ");
                chatText = waitAndHandleUserInput();
                // |4|encChatMsg|iv|checkSum
                message = Message.getP2PChatMsg(chatText, peerToPeerSecretKey);
                socketChannel.register(localSelector, SelectionKey.OP_WRITE, ByteBuffer.wrap(message.getBytes()));
                break;
            // case "9":
            // /**
            // * incoming message:
            // * |9|chatMessage
            // */
            // set the peerClientId to the value from the ticket
            // System.out.println("Peer@" + this.peerClientId + ": " + payload[2]);
            // System.out.println("Enter your message: ");
            // message = "|9|" + waitAndHandleUserInput();
            // socketChannel.register(localSelector, SelectionKey.OP_WRITE,
            // ByteBuffer.wrap(message.getBytes()));
            // break;
            default:
                break;
        }
    }

    public static String waitAndHandleUserInput() throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String input = reader.readLine();
        return input;
    }

    private void accept(Selector locaSelector, SelectionKey key) throws Exception {
        ServerSocketChannel serverSocketChannel = (ServerSocketChannel) key.channel();
        SocketChannel socketChannel = serverSocketChannel.accept();
        if (socketChannel != null) {
            System.out.println("New connection accepted by ClientIncomingConnectionListener.");
            socketChannel.configureBlocking(false);
            socketChannel.register(locaSelector, SelectionKey.OP_READ);
        }
    }
}