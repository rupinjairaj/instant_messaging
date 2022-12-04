import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Client {

    private static PrivateKey clientPrivateKey;
    private static PublicKey clientPublicKey;
    private static PublicKey serverPublicKey;

    private static int clientID;
    private static String clientHostName;
    private static int clientPort;
    private static String serverHostName;
    private static int serverPort;
    private static boolean clientStatus = true; // True - available, False - busy

    private static void parseArguments(String[] args) {
        /**
         * command line arguments order:
         * clientID hostName clientPort serverHostName serverPort
         */
        clientID = Integer.parseInt(args[0]);
        clientHostName = args[1];
        clientPort = Integer.parseInt(args[2]);
        serverHostName = args[3];
        serverPort = Integer.parseInt(args[4]);
    }

    private static void setupKey() throws Exception {
        String rsaKeyParentPath = "../keys";
        // String rsaKeyParentPath = "/Users/rupinjairaj/projects/utd/sem3/network_security/project/instant_messaging_system/keys";
        String clientKeyFilePath = rsaKeyParentPath + "/client" + clientID;
        String serverKeyFilePath = rsaKeyParentPath + "/server";
        clientPrivateKey = Crypto.getPrivateKey(Crypto.readKeyFromFile(clientKeyFilePath + "/rsa"));
        clientPublicKey = Crypto.getPublicKey(Crypto.readKeyFromFile(clientKeyFilePath + "/rsa.pub"));
        serverPublicKey = Crypto.getPublicKey(Crypto.readKeyFromFile(serverKeyFilePath + "/rsa.pub"));
    }

    public static void main(String[] args) throws Exception {

        // parse and setup command line arguments
        parseArguments(args);

        // setup keys in memory
        setupKey();

        // setting up client's incoming message handler thread
        IncomingMessageHandler incomingMessageHandler = new IncomingMessageHandler(
                clientPrivateKey, clientPublicKey,
                clientID, clientHostName,
                clientPort, serverHostName, serverPort);
        Thread incomingMessageHandlerThread = new Thread(incomingMessageHandler, "th_incomingMessageHandler");
        incomingMessageHandlerThread.start();

    }

    public String waitAndHandleUserInput() throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String input = reader.readLine();
        return input;
    }

}
