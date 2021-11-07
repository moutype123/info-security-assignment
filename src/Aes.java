import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Aes {
	
	private final String alg = "AES/CBC/PKCS5Padding";
	private final KeyDB keyDB;
	
	public Aes(KeyDB keyDB) {
		this.keyDB = keyDB;
	}

	public byte[] encrytion(String message) throws Exception {

		SecretKeySpec secretKeySpec = new SecretKeySpec(keyDB.getSecretKey(), "AES");
		
		Cipher cipher = Cipher.getInstance(alg);
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(keyDB.getIv()));

		return Base64.getEncoder().encode(cipher.doFinal((message.getBytes(StandardCharsets.UTF_8))));
		
	}
	
	public String decrytion(String message) throws Exception {
		
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyDB.getSecretKey(), "AES");
		Cipher cipher = Cipher.getInstance(alg);
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(keyDB.getIv()));
		
		return new String(cipher.doFinal(Base64.getDecoder().decode(message)));
	}
	
}
