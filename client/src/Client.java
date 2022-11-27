import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Client {

    private static Logger logger = Logger.getLogger("com.instant_messaging");

    private static int clientID = 0;
    private static String clientPrivateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLSBFJ/Jvt3xLsqNRjJCFT9zzE7wVTeXkvx6bV22lAOVdbAHOZuADCO/gMnRm/+wOON8F8ajyaex5LARDyRPOL2KdbHtiCRKMHfwqqyyQueAR21VzWAr1PUFzJlXquUbxC17zzuvHlF16RjQvgJNp2XCZUf+RhsX8KWFmvJ60Ruwfr+1yXq9FK4j8ZKaznDuERiYQAyOMPlc72VbqAeSGDmoH70nZsHYYhAsSNT5Qqq5qbJN5RAGTj5qBB+KqUc6g4LWanjpTpf7IxVjkiS2bI1FZZZs/J7GYihLs9We5Z4nfc7IGc1mF2u5nuzdR4Ev9hFpKbcuqNAiZBjJXxWUjrAgMBAAECggEAYQwJUPibmo7GUpxxNNmBXbwpU11G/ih+bgyTPgKvNz2I0kWfarIZDqGhlKgFrI0SD/nXUeXIA/omJqmeJQM9ADURBKPvuhU5fbEtbwdnQRYED5Vh6jvJlA1qFsTZmlIkHgcvym4j4HptJ/CdzEbb0ujAVdPuvKMH4vD18/RtoAn/y48JZvuF2p/YAuwhjxvGlBIqrhXq8aCrDARAMH2X5/UWEXG2WPKxp+Vbt5yUAn17yaLpizqDsGMyZN9+ZLyZuy4rciqgnyX/CFSX+asZ39cxYJDxvW7p3yYCAbPNzYX/ndMJKbhn2HnDcmpgG1U2Ul3CsqoeJAN9XMOiCwHzhQKBgQDbN7GHn5mpOcox0layWmli4CuznNA65+wD76wM6bK4hL12xpy86ZHcrQEJCq1zbKIjhplQsSvjRN06V7ORQGNg7B6jJFv7vzdC3VTC1xnn6jmGIDEdjqthEQaHheZ4XCaMfFJrhsjedvqHzFOkzhtzruummBSylJcdojJvIgw9DwKBgQDtY9rXR8QXdsOdXvGsn9sAvJi3KrhEVgbTvykOfRKO9u1CulC3HHsOKrkS4kr5cmSMA20mniG/LkEkGNocU0QQVLxV3D5lB7djSyfYpksKPcAs7wPjhqji0TThVjDkAIJrAzzlOm4hZhu4y8rpUeyRaifWMzgM498fnMEdGKuuZQKBgBznVff82iTO4tL42ceAVj7cMcbn2Si7JYpLUpMNSSw9DEIZ49agsUO4Z9eKWd5LJ4GpoJNcGN5JWSX1JE71f2TrHQsDo0EpMB8X0bIy7E6Aun7txawRAJW2yfaaeA3MkKSbS76zsc5rP5MiJLEpH8N7/8QibzAwmVAl76JpidWPAoGBALSMzuQPtEe4T31AugT2LAY6athdCHsJBvZDnQFlBRlxGvE2ba9nXPxgaBTBwg5I/8oxzPGjMb2Le4Xt1O3YMptNJ1USRu5mWQePIMY5bDdk0eYa/9UsFQU14sdD27l93bNwaf9aWmrSk2EQtsqQQaIzoArdN9Mt+QS9H2921RS1AoGBAMPbZ1Mp1P/TXePwcasKlHxcD6TJhvKqeaTye88fY4XLk8tH6fIJH2UhKcb3sKOBJ5FgAQN38USUrXUIoohswbWzdphRTtarz+21s2AxeL+otRGVRHLvryDUcH9R28Qp3JzjuFGA4rHJ4ZLdHbFlTgF3MEEwObZIvMI38aCCLBvm";
    private static String clientPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy0gRSfyb7d8S7KjUYyQhU/c8xO8FU3l5L8em1dtpQDlXWwBzmbgAwjv4DJ0Zv/sDjjfBfGo8mnseSwEQ8kTzi9inWx7YgkSjB38KqsskLngEdtVc1gK9T1BcyZV6rlG8Qte887rx5RdekY0L4CTadlwmVH/kYbF/ClhZryetEbsH6/tcl6vRSuI/GSms5w7hEYmEAMjjD5XO9lW6gHkhg5qB+9J2bB2GIQLEjU+UKquamyTeUQBk4+agQfiqlHOoOC1mp46U6X+yMVY5IktmyNRWWWbPyexmIoS7PVnuWeJ33OyBnNZhdruZ7s3UeBL/YRaSm3LqjQImQYyV8VlI6wIDAQAB";
    private static String serverPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtLOpqKwJpcIsojFAfVf1oHRWgTb7nZEwC4T7jQENl1Bxd1vgHFlEM+czEzKz/PHE+fqhcaG4MS4LL9zvI7AWNwc9IErz4bTdHVMtSu7yIzIxCswaYGzUeVVKtXdgh/Lz4sFTzDi/13fLqC3QPC5kWbbwz19rASzRnsH29zrYfo3J0JqsBV/bK/vK10WgUm14cLwmhapEOZiV04odXv8/dFo9WDQ8vTBPymko88y5YxQ6gHLZLpKh3+B0ptSV+LNfwTWwqghQprFuES0meD7uJKpHM1r+jaJhPRCBvVLSxJvePckyuKt3aKgQhmPVryrpewaQFQCIbrKnkQ5H0TiMnwIDAQAB";
    private static String clientServerSessionKey = "";
    private static String peerPublicKey = "";
    private static String hostName = "localhost";
    private static int port = 3000;
    private static String serverHostName = "localhost";
    private static int serverPort = 7000;

    public static void main(String[] args) throws Exception {

        SecureRandom random = new SecureRandom();

        Selector selector = Selector.open();
        var serverHandler = new ServerHandler();
        if (!serverHandler.establishConnection(Client.serverHostName,
                Client.serverPort)) {
            return;
        }

        serverHandler.serverSocketChannel.register(selector, SelectionKey.OP_READ);

        int ranNum = random.nextInt();
        String ranNumSign = Crypto.rsaSign(String.valueOf(ranNum), Crypto.getPrivateKey(clientPrivateKey));

        if (!serverHandler.sendAuthMessage(
                Message.getC2SAuthMsg(Client.clientID, Client.hostName, Client.port, ranNum, ranNumSign))) {
            return;
        }

        while (true) {
            int selected = selector.select();
            System.out.println("Selected: " + selected + " key(s)");

            Iterator<SelectionKey> keysIterator = selector.selectedKeys().iterator();
            while (keysIterator.hasNext()) {
                SelectionKey key = keysIterator.next();

                if (key.isAcceptable()) {

                }

                if (key.isReadable()) {
                    requestHandler(selector, key);
                }

                if (key.isWritable()) {

                }

                keysIterator.remove();
            }

            // use user input here to do operations like request server for
            // info of all clients, connect with a specific client from the
            // list of clients returened by the server and chat with the
            // client.
        }

    }

    private static void requestHandler(Selector selector, SelectionKey key) throws Exception {

        SocketChannel socketChannel = (SocketChannel) key.channel();

        ByteBuffer buffer = ByteBuffer.allocate(1024);
        int read = socketChannel.read(buffer);
        logger.log(Level.INFO, "Client read '" + read + "' byte(s)");

        buffer.flip();
        byte[] bytes = new byte[buffer.limit()];
        buffer.get(bytes);

        String message = new String(bytes, StandardCharsets.UTF_8);
        logger.log(Level.INFO, "Client received: " + message);

        String[] payload = message.split("\\|");

        switch (payload[1]) {
            case "3":
                String cipherText = payload[2];
                PrivateKey pr = Crypto.getPrivateKey(clientPrivateKey);
                String plainText = Crypto.rsaDecrypt(cipherText, pr);
                clientServerSessionKey = plainText;
                System.out.println("Session key obtained: " + plainText);
                break;
            case "4":
                break;
            case "5":
                break;
            case "6":
                break;
            case "7":
                break;
            default:
                break;
        }

    }

}
