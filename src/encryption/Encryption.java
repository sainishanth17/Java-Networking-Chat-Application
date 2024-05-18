package encryption;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {

	private static final String RSA = "RSA";
	private static final String AES = "AES";
	
	public static String encrypt(Key key, String input) 
			throws NoSuchPaddingException, NoSuchAlgorithmException,
		    InvalidAlgorithmParameterException, InvalidKeyException,
	    BadPaddingException, IllegalBlockSizeException {
	    
	    Cipher cipher = Cipher.getInstance(AES);
	    cipher.init(Cipher.ENCRYPT_MODE, key);
	    byte[] cipherText = cipher.doFinal(input.getBytes());
	    return Base64.getEncoder()
	        .encodeToString(cipherText);
	}
	
	public static String decrypt(Key key, String cipherText) 
			throws NoSuchPaddingException, NoSuchAlgorithmException,
		    InvalidAlgorithmParameterException, InvalidKeyException,
	    BadPaddingException, IllegalBlockSizeException {
	    
	    Cipher cipher = Cipher.getInstance(AES);
	    cipher.init(Cipher.DECRYPT_MODE, key);
	    byte[] plainText = cipher.doFinal(Base64.getDecoder()
	        .decode(cipherText));
	    return new String(plainText);
	}
	

	public static byte[] pkEncrypt(Key key, byte[] plaintext) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, 
			InvalidKeyException, IllegalBlockSizeException, 
			BadPaddingException
	{
	    Cipher cipher = Cipher.getInstance(RSA);// /ECB/OAEPWithSHA1AndMGF1Padding");   
	    cipher.init(Cipher.ENCRYPT_MODE, key);  
	    return cipher.doFinal(plaintext);
	}

	public static byte[] pkDecrypt(Key key, byte[] ciphertext) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, 
			InvalidKeyException, IllegalBlockSizeException, 
			BadPaddingException
	{
	    Cipher cipher = Cipher.getInstance(RSA); // /ECB/OAEPWithSHA1AndMGF1Padding");   
	    cipher.init(Cipher.DECRYPT_MODE, key);  
	    return cipher.doFinal(ciphertext);
	}

	public static Key generateAESKey(byte[] sequence) {

	    System.out.println("generated key with bytes "+ Arrays.toString(sequence));
	    return new SecretKeySpec(sequence, "AES");
	}
	
	public static byte[] generateSeed() {
		SecureRandom secureRandom = new SecureRandom();
		byte[] secureRandomKeyBytes = new byte[16];
	    secureRandom.nextBytes(secureRandomKeyBytes);
	    return secureRandomKeyBytes;
	}
	

	public static PrivateKey readPrivateKey(String filename)
		    throws Exception {

	    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

	      PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
	      KeyFactory kf = KeyFactory.getInstance(RSA);
	      return kf.generatePrivate(spec);
	}
	
	public static PublicKey readPublicKey(String keyString)
		    throws Exception {

	    byte[] keyBytes = Base64.getDecoder().decode(keyString);

	    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
	      KeyFactory kf = KeyFactory.getInstance(RSA);
	      return kf.generatePublic(spec);
	      
	}
	
}
