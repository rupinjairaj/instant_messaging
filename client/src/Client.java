import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Client {

    private static Logger logger = Logger.getLogger("com.instant_messaging");

    public static void main(String[] args) throws Exception {

        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
        String message;

        SocketChannel socketChannel = SocketChannel.open(new InetSocketAddress("localhost", 7000));
        logger.log(Level.INFO, "Client running...");

        while ((message = stdIn.readLine()) != "bye") {

            ByteBuffer buffer = ByteBuffer.wrap(message.getBytes());
            socketChannel.write(buffer);
            logger.log(Level.INFO, "Client sent: " + message);

            int totalRead = 0;
            while (totalRead < message.getBytes().length) {
                buffer.clear();

                int read = socketChannel.read(buffer);
                logger.log(Level.INFO, "Client read '" + read + "' byte(s)");
                if (read <= 0) {
                    break;
                }

                totalRead += read;

                buffer.flip();
                logger.log(Level.INFO, "Client received '" + StandardCharsets.UTF_8.newDecoder().decode(buffer));
            }
        }
        socketChannel.close();
        logger.log(Level.INFO, "Client disconnected");
    }

}
