import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayOutputStream;

public class Crypto {

	private static final String SHA256_ALGO = "SHA-256";

	public static SecretKey generateSessionKey() throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		return keyGen.generateKey();
	}

	public static IvParameterSpec generateIv() {
		byte[] iv = new byte[8];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	public static byte[] generateHash(byte[] key, byte[] input) throws Exception {
		ByteArrayOutputStream bStream = new ByteArrayOutputStream();
		bStream.write(key);
		bStream.write(input);

		byte[] valToHash = bStream.toByteArray();
		MessageDigest messageDigest = MessageDigest.getInstance(SHA256_ALGO);
		return messageDigest.digest(valToHash);
	}

	public static List<byte[]> splitArray(byte[] source, int chunkSize) {
		List<byte[]> result = new ArrayList<byte[]>();
		int start = 0;

		while (start < source.length) {
			int end = Math.min(source.length, start + chunkSize);
			result.add(Arrays.copyOfRange(source, start, end));
			start += chunkSize;
		}

		return result;
	}

	public static byte[] xor(byte[] a1, byte[] a2) {
		byte[] temp = new byte[a1.length];
		for (int i = 0; i < a1.length; i++) {
			temp[i] = (byte) (a1[i] ^ a2[i]);
		}

		return temp;
	}

	public static String rollingEncrypt(String plainText, IvParameterSpec iv, SecretKey key) throws Exception {
		byte[] plainTextBytes = plainText.getBytes();
		byte[] keyStringBytes = key.getEncoded();
		byte[] initVec = iv.getIV();

		List<byte[]> plainTextChunks = splitArray(plainTextBytes, 32);
		System.out.println(plainTextChunks);

		ByteArrayOutputStream cipherByteStream = new ByteArrayOutputStream();

		byte[] currVec = initVec;
		for (byte[] p_i : plainTextChunks) {
			byte[] b_i = generateHash(keyStringBytes, currVec);
			byte[] c_i = xor(p_i, b_i);
			currVec = c_i;
			cipherByteStream.write(c_i);
		}

		return Base64.getEncoder().encodeToString(cipherByteStream.toByteArray());
	}

	public static String rollingDecrypt(String cipherText, IvParameterSpec iv, SecretKey key) throws Exception {
		byte[] cipherTextBytes = Base64.getDecoder().decode(cipherText);
		byte[] keyStringBytes = key.getEncoded();
		byte[] initVec = iv.getIV();

		List<byte[]> cipherTextChunks = splitArray(cipherTextBytes, 32);
		System.out.println(cipherTextChunks);

		ByteArrayOutputStream plaintextByteStream = new ByteArrayOutputStream();

		byte[] currVec = initVec;
		for (byte[] c_i : cipherTextChunks) {
			byte[] b_i = generateHash(keyStringBytes, currVec);
			byte[] p_i = xor(c_i, b_i);
			currVec = c_i;
			plaintextByteStream.write(p_i);
		}

		return plaintextByteStream.toString();
	}

	public static KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048, new SecureRandom());
		KeyPair pair = generator.generateKeyPair();

		return pair;
	}

	public static PublicKey getPublicKey(String base64PublicKey) throws Exception {
		PublicKey publicKey = null;
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		publicKey = keyFactory.generatePublic(keySpec);
		return publicKey;
	}

	public static PrivateKey getPrivateKey(String base64PrivateKey) throws Exception {
		PrivateKey privateKey = null;
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
		KeyFactory keyFactory = null;
		keyFactory = KeyFactory.getInstance("RSA");
		privateKey = keyFactory.generatePrivate(keySpec);
		return privateKey;
	}

	public static String rsaEncrypt(String plainText, PublicKey publicKey) throws Exception {
		Cipher encryptCipher = Cipher.getInstance("RSA");
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

		byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

		return Base64.getEncoder().encodeToString(cipherText);
	}

	public static String rsaDecrypt(String cipherText, PrivateKey privateKey) throws Exception {
		byte[] bytes = Base64.getDecoder().decode(cipherText);

		Cipher decriptCipher = Cipher.getInstance("RSA");
		decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

		return new String(decriptCipher.doFinal(bytes), UTF_8);
	}

	public static String rsaSign(String plainText, PrivateKey privateKey) throws Exception {
		Signature privateSignature = Signature.getInstance("SHA256withRSA");
		privateSignature.initSign(privateKey);
		privateSignature.update(plainText.getBytes(UTF_8));

		byte[] signature = privateSignature.sign();

		return Base64.getEncoder().encodeToString(signature);
	}

	public static boolean rsaVerify(String plainText, String signature, PublicKey publicKey) throws Exception {
		Signature publicSignature = Signature.getInstance("SHA256withRSA");
		publicSignature.initVerify(publicKey);
		publicSignature.update(plainText.getBytes(UTF_8));

		byte[] signatureBytes = Base64.getDecoder().decode(signature);

		return publicSignature.verify(signatureBytes);
	}

}
