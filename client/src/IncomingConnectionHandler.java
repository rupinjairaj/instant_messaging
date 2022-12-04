import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Iterator;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class IncomingConnectionHandler implements Runnable {

    private ServerSocketChannel clientServerSocketChannel;
    private String hostName;
    private int port;
    private SecretKey peerToPeerSecretKey;
    private int peerClientId;

    public IncomingConnectionHandler(String hostName, int port) {
        this.hostName = hostName;
        this.port = port;
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
            case "6":
                /**
                 * incoming message:
                 * |6|clientID|ticketForPeer
                 */
                String ticketForClient = payload[3];
                System.out.println("Client received p2p session key: " + ticketForClient);
                byte[] peerToPeerSecretKeyBytes = Base64.getDecoder().decode(ticketForClient);
                // saving the client-server session key in-memory
                this.peerToPeerSecretKey = new SecretKeySpec(peerToPeerSecretKeyBytes, 0,
                        peerToPeerSecretKeyBytes.length,
                        "AES");
                message = "|7|aNewChallenge|responseToGivenChallenge|dataFromTicketForServer";
                socketChannel.register(localSelector, SelectionKey.OP_WRITE, ByteBuffer.wrap(message.getBytes()));
                break;
            case "8":
                /**
                 * incoming message:
                 * |8|responseToANewChallenge
                 */
                // verify response and if valid send the first message
                message = "|8|sessionEstablished";
                socketChannel.register(localSelector, SelectionKey.OP_WRITE, ByteBuffer.wrap(message.getBytes()));
                break;
            case "9":
                /**
                 * incoming message:
                 * |9|chatMessage
                 */
                // TODO: set the peerClientId to the value from the ticket
                System.out.println("Peer@" + this.peerClientId + ": " + payload[2]);
                System.out.println("Enter your message: ");
                message = "|9|" + waitAndHandleUserInput();
                socketChannel.register(localSelector, SelectionKey.OP_WRITE, ByteBuffer.wrap(message.getBytes()));
                break;
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