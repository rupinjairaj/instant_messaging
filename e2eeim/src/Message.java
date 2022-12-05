import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Message {

    /**
     * payload pattern for client to server communication:
     * |messageTypeCode|clientId|[...|...|]
     * supported messageTypeCode:
     * ** 0 - auth
     * **** auth message request payload:
     * |0|clientId|randomNumber|signedRandomNumber]hostname|signedHostName|port|signedPort|
     * **** auth message response payload:
     * |0|encrypted(randomNumber-1)|clientPublicKey(sessionKey)|iv|hash(sessionKey|payload|sessionKey)|
     * 
     * ** 1 - requesting client list
     * **** client list request payload:
     * |1|clientId|
     * **** client list response payload:
     * |1|encryptedClientList|iv|hash(sessionKey|payload|sessionKey)|
     * 
     * ** 2 - requesting server for p2p session info
     * **** client p2p session info request:
     * |2|clientId|encryptedPeerId|iv|hash(sessionKey|payload|sessionKey)
     * **** server p2p session info response:
     * |2|sourceClientEncrypt(incomingIv|destPeerId|destHostName|destHostPort|p2pSessionKey|destPeerTicket|destIv)|sourceIv|hash(sessionKey|payload|sessionKey)|
     * destPeerTicket -
     * destClientEncrypt(p2pSessionKey|sourcePeerId|expirationTime)
     * **** peer to peer ticket:
     * |2|ticketForPeer|iv|p2pSessionKeyEncrypted(timestamp)|timeEncIv
     * 
     * ** 3 - peer's response to peer's challenge
     * |3|p2pSessionKeyEncrypt(originalChallenge+1)|iv
     * 
     * ** 4 - p2p chat messages:
     * |4|encChatMsg|iv|checkSum;
     * 
     * ** 5 - client sends server their status
     * |5|clientId|encrypted(status)|iv|hash(sessionKey|payload|sessionKey)
     */
    String payload;

    // client payloads
    public static String getC2SAuthMsg(int clientID, String hostName, int port, int randomNumber, PrivateKey key) {
        // |0|clientId|randomNumber|signedRandomNumber]hostname|signedHostName|port|signedPort
        String ranNumSign = Crypto.rsaSign(String.valueOf(randomNumber), key);
        String signedHostName = Crypto.rsaSign(hostName, key);
        String signedHostPort = Crypto.rsaSign(String.valueOf(port), key);
        String payload = "|0|" + clientID + "|" + randomNumber + "|" + ranNumSign + "|" + hostName + "|"
                + signedHostName + "|" + port + "|" + signedHostPort + "|";
        return payload;
    }

    public static String getC2SPeerListReqMsg(int clientID) {
        return "|1|" + clientID;
    }

    public static String getC2SPeerSessionReqMsg(int clientID, String peerID, SecretKey sessionKey) {
        // |2|clientId|encryptedPeerId|iv|hash(sessionKey|payload|sessionKey)
        IvParameterSpec iv = Crypto.generateIv();
        String peerIdCipherText = Crypto.rollingEncrypt(peerID, iv, sessionKey);
        String base64IvParameterSpec = Base64.getEncoder().encodeToString(iv.getIV());
        String responsePayload = "|2|" + clientID + "|" + peerIdCipherText + "|" + base64IvParameterSpec;
        byte[] checkSum = Crypto.generateCheckSum(sessionKey.getEncoded(), responsePayload.getBytes());
        String base64EncodedCheckSum = Base64.getEncoder().encodeToString(checkSum);
        return responsePayload + "|" + base64EncodedCheckSum;
    }

    public static String getC2SStatusUpdateMsg(int clientId, boolean status, SecretKey clientServerSessionKey) {
        // |5|clientId|encrypted(status)|iv|hash(sessionKey|payload|sessionKey)
        String statusText = status ? "idle" : "busy";
        IvParameterSpec iv = Crypto.generateIv();
        String statusCipher = Crypto.rollingEncrypt(statusText, iv, clientServerSessionKey);
        System.out.println("In Message.java - statusCipher: " + statusCipher);
        String base64IvParameterSpec = Base64.getEncoder().encodeToString(iv.getIV());
        String checkSumPayload = "|5|" + clientId + "|" + statusText + "|" + base64IvParameterSpec;
        byte[] checkSum = Crypto.generateCheckSum(clientServerSessionKey.getEncoded(), checkSumPayload.getBytes());
        String base64EncodedCheckSum = Base64.getEncoder().encodeToString(checkSum);
        return "|5|" + clientId + "|" + statusCipher + "|" + base64IvParameterSpec + "|" + base64EncodedCheckSum;
    }

    public static String getP2PSessionMsg(String ticketForPeer, String iv, SecretKey p2pSecretKey,
            long p2pTime) {
        // |2|ticketForPeer|iv|p2pSessionKeyEncrypted(timestamp)|timeEncIv
        IvParameterSpec ivParameterSpec = Crypto.generateIv();
        String p2pTimeEnc = Crypto.aesEncrypt(Long.toString(p2pTime), ivParameterSpec, p2pSecretKey);
        return "|2|" + ticketForPeer + "|" + iv + "|" + p2pTimeEnc + "|"
                + Base64.getEncoder().encodeToString(ivParameterSpec.getIV());
    }

    public static String getP2PChallengeResMsg(long p2pTimePlusOne, SecretKey p2pSecretKey) {
        // |3|p2pSessionKeyEncrypt(originalChallenge+1)|iv
        IvParameterSpec ivParameterSpec = Crypto.generateIv();
        String p2pTimeEnc = Crypto.aesEncrypt(Long.toString(p2pTimePlusOne), ivParameterSpec, p2pSecretKey);
        return "|3|" + p2pTimeEnc + "|" + Base64.getEncoder().encodeToString(ivParameterSpec.getIV());
    }

    public static String getP2PChatMsg(String chatMessage, SecretKey p2pKey) {
        // |4|encChatMsg|iv|checkSum
        IvParameterSpec ivParameterSpec = Crypto.generateIv();
        byte[] checkSumByte = Crypto.generateCheckSum(p2pKey.getEncoded(), chatMessage.getBytes());
        String checkSum = Base64.getEncoder().encodeToString(checkSumByte);
        String encChatMsg = Crypto.rollingEncrypt(chatMessage, ivParameterSpec, p2pKey);
        return "|4|" + encChatMsg + "|" + Base64.getEncoder().encodeToString(ivParameterSpec.getIV()) + "|" + checkSum;
    }

    // server payloads
    public static String getS2CAuthResMsg(int randomNumber, PublicKey key,
            Map<Integer, SecretKey> clientSessionKey, int clientID) {

        // |messageTypeCode|encrypted(randomNumber-1)|clientPublicKey(sessionKey)|iv|hash(sessionKey|payload|sessionKey)|
        // generate a session key here for client-server communications
        SecretKey sessionKey = Crypto.generateSessionKey();
        clientSessionKey.put(clientID, sessionKey);
        // Encrypt the sessionKey with the client's public key
        String base64EncodedSessionKey = Base64.getEncoder().encodeToString(sessionKey.getEncoded());
        String encryptedSessionKey = Crypto.rsaEncrypt(base64EncodedSessionKey, key);
        IvParameterSpec iv = Crypto.generateIv();
        String randomNumMinus1Encrypted = Crypto.aesEncrypt(String.valueOf(randomNumber - 1),
                iv,
                sessionKey);
        String base64IvParameterSpec = Base64.getEncoder().encodeToString(iv.getIV());
        String responsePayload = "|0|" + randomNumMinus1Encrypted + "|" + encryptedSessionKey + "|"
                + base64IvParameterSpec;
        byte[] checkSum = Crypto.generateCheckSum(sessionKey.getEncoded(), responsePayload.getBytes());
        String base64EncodedCheckSum = Base64.getEncoder().encodeToString(checkSum);
        return responsePayload + "|" + base64EncodedCheckSum;
    }

    public static String getS2CPeerListResMsg(String peerIDs, SecretKey sessionKey) {
        // |1|encryptedClientList|iv|hash(sessionKey|payload|sessionKey)
        IvParameterSpec iv = Crypto.generateIv();
        String peerIdCipherText = Crypto.rollingEncrypt(peerIDs, iv, sessionKey);
        String base64IvParameterSpec = Base64.getEncoder().encodeToString(iv.getIV());
        String responsePayload = "|1|" + peerIdCipherText + "|" + base64IvParameterSpec;
        byte[] checkSum = Crypto.generateCheckSum(sessionKey.getEncoded(), responsePayload.getBytes());
        String base64EncodedCheckSum = Base64.getEncoder().encodeToString(checkSum);
        return responsePayload + "|" + base64EncodedCheckSum;
    }

    public static String getS2CPeerSessionResMsg(int sourcePeerId, int destPeerId, SecretKey srcClientSessionKey,
            SecretKey destClientSessionKey, String destPeerPort, String destPeerHostName, String incomingIv) {

        // |2|sourceClientEncrypt(incomingIv|destPeerId|destHostName|destHostPort|p2pSessionKey|destPeerTicket|destIv)|sourceIv|hash(sessionKey|payload|sessionKey)|
        // destPeerTicket -
        // destClientEncrypt(p2pSessionKey|sourcePeerId|expirationTime)

        // -- Start building destPeerTicket
        SecretKey p2pSessionKey = Crypto.generateSessionKey();
        String base64EncodedSessionKey = Base64.getEncoder().encodeToString(p2pSessionKey.getEncoded());
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        Instant instant = timestamp.toInstant();
        long expirationTime = instant.toEpochMilli() + (long) (1000 * 60 * 10);
        String ticketForDestPeer = base64EncodedSessionKey + "|" + sourcePeerId + "|" + expirationTime;
        IvParameterSpec destPeerIv = Crypto.generateIv();
        String encryptedTicketForDestPeer = Crypto.rollingEncrypt(ticketForDestPeer, destPeerIv, destClientSessionKey);
        String finalDestTicket = encryptedTicketForDestPeer + "|"
                + Base64.getEncoder().encodeToString(destPeerIv.getIV());
        // -- End building destPeerTicket

        IvParameterSpec sourceIv = Crypto.generateIv();
        String sourcePeerRes = incomingIv + "|" + destPeerId + "|" + destPeerHostName + "|" + destPeerPort + "|"
                + base64EncodedSessionKey + "|" + finalDestTicket;
        String sourcePeerResEnc = Crypto.rollingEncrypt(sourcePeerRes, sourceIv, srcClientSessionKey);
        byte[] checkSum = Crypto.generateCheckSum(srcClientSessionKey.getEncoded(), sourcePeerRes.getBytes());
        String base64EncodedCheckSum = Base64.getEncoder().encodeToString(checkSum);

        String finalResponse = "|2|" + sourcePeerResEnc + "|" + Base64.getEncoder().encodeToString(sourceIv.getIV())
                + "|" + base64EncodedCheckSum;

        return finalResponse;
    }

}
