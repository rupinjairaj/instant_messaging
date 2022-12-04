import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Message {

    /**
     * payload pattern:
     * ** {author}|{messageType}
     * 
     * author: client/server
     * messageType:
     * ** 0 - auth
     * ** 1 - requesting client list
     * ** 2 - requesting session with client
     * ** 3 - server acknowledges auth // server response to 0
     * ** 4 - server responds with client list // server response to 1
     * ** 5 - server responds with session key for 2 clients // server response to 2
     * ** 6 - client connects with peer and sends session key
     * ** 7 - client to client messages
     * 
     * for messageType 0
     * |0|randomNumber|clientID|clientHostName|clientIncomingPort
     * 
     * for messageType 1
     * |1|
     * 
     * for messageType 2
     * |2|fromClientID|toClientID
     * 
     * for messageType 3
     * |3|isAuthSuccess
     * 
     * for messageType 4
     * |4|clientID1|clientID2|...
     * 
     * for messageType 5
     * |5|clientID1|clientID2|base64SessionKey|
     * 
     * for messageType 6
     * |6|clientID1|clientID2|sessionKey|destPort|destClientHostName
     * 
     * for messageType 7
     * |7|clientID1|clienID2|chatMessage
     */
    String payload;

    // client payloads
    public static String getC2SAuthMsg(int clientID, String hostName, int port,
            int randomNumber, String signedRandomNumber) {
        String payload = "|0|" + clientID + "|" + randomNumber + "|" + signedRandomNumber + "|" + hostName + "|" + port;
        return payload;
    }

    public static String getC2SPeerListReqMsg(int clientID) {
        return "|1|" + clientID;
    }

    public static String getC2SPeerSessionReqMsg(int clientID, String peerID, SecretKey sessionKey) {
        IvParameterSpec iv = Crypto.generateIv();
        String cipherText = Crypto.rollingEncrypt(peerID, iv, sessionKey);
        return "|2|" + clientID + "|" + cipherText + "|" + Base64.getEncoder().encodeToString(iv.getIV());
    }

    // TODO: encrypt this payload
    public static String getP2PSessionMsg(int clientID, String ticketForPeer) {
        return "|6|" + clientID + "|" + ticketForPeer;
    }

    // TODO: encrypt this payload
    public static String getP2PChatMsg(String chatMessage) {
        return "|7|" + chatMessage;
    }

    // server payloads
    public static String getS2CAuthResMsg(String message) {
        return "|3|" + message;
    }

    public static String getS2CPeerListResMsg(String peerIDs, SecretKey sessionKey) {
        IvParameterSpec iv = Crypto.generateIv();
        String peerIdCipherText = Crypto.rollingEncrypt(peerIDs, iv, sessionKey);
        return "|4|" + peerIdCipherText + "|" + Base64.getEncoder().encodeToString(iv.getIV());
    }

    public static String getS2CPeerSessionResMsg(int clientID1, int clientID2, SecretKey srcClientSessionKey,
            SecretKey destClientSessionKey, String desClientPort, String destClientHostName) {
        SecretKey sessionKey = Crypto.generateSessionKey();
        String base64EncodedSessionKey = Base64.getEncoder().encodeToString(sessionKey.getEncoded());
        return "|5|" + clientID1 + "|" + clientID2 + "|" + base64EncodedSessionKey + "|" + desClientPort + "|"
                + destClientHostName; // TODO: Encrypt this
    }

}
