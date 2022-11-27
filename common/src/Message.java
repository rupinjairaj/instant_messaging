import java.security.Key;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
     * |5|clientID1|clientID2|sessionKey
     * 
     * for messageType 6
     * |6|clientID1|clientID2|sessionKey
     * 
     * for messageType 7
     * |7|clientID1|clienID2|chatMessage
     */
    String payload;

    // client payloads
    public static String getC2SAuthMsg(int clientID, String hostName, int port,
            int randomNumber, String signedRandomNumber)
            throws Exception {
        String payload = "|0|" + clientID + "|" + randomNumber + "|" + signedRandomNumber + "|" + hostName + "|" + port;
        return payload;
    }

    public static String getC2SPeerListReqMsg(int clientID) {
        return "|1|" + clientID;
    }

    public static String getC2SPeerSessionReqMsg(String peerID) {
        return "|2|" + peerID;
    }

    public static String getP2PSessionMsg() {
        return "";
    }

    public static String getP2PChatMsg() {
        return "";
    }

    // server payloads
    public static String getS2CAuthResMsg(String message) {
        return "|3|" + message;
    }

    public static String getS2CPeerListResMsg(String peerIDs, String base64EncodeSessionKey) throws Exception {
        IvParameterSpec iv = Crypto.generateIv();
        byte[] decodedKey = Base64.getDecoder().decode(base64EncodeSessionKey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        String payload = Crypto.rollingEncrypt(peerIDs, iv, originalKey);
        return "|4|" + payload + "|" + Base64.getEncoder().encodeToString(iv.getIV());
    }

    public static String getS2CPeerSessionResMsg(String clientID1, String clientID2, String sessionKey) {
        return "|5|" + clientID1 + "|" + clientID2 + "|" + sessionKey;
    }

}
