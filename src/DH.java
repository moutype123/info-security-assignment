import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;

public class DH {	
	
	private KeyAgreement keyAgreement;
	public KeyPair keyPair;
	
	public KeyDB keyDB; 
	public PublicKey publicKey;
	
	public byte[] generatePublicKey() throws NoSuchAlgorithmException, InvalidKeyException {
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
		
		kpg.initialize(2048);
		
        this.keyPair = kpg.generateKeyPair();
        
        this.keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(this.keyPair.getPrivate());
	    //public key Àü¼Û
	    return keyPair.getPublic().getEncoded();
	    
	}
	
	public byte[] getSenderPublicKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException {
		
		PublicKey senderPublicKey = KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(encodedKey));
				
		KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DH");
		
		keyPair.initialize(((DHPublicKey)senderPublicKey).getParams());
	    
	    this.keyPair = keyPair.generateKeyPair();
	    
	    this.keyAgreement = KeyAgreement.getInstance("DH");
	    keyAgreement.init(this.keyPair.getPrivate());
	    
	    this.makeSecreteKey(encodedKey);
	    
	    return this.keyPair.getPublic().getEncoded();
		
	}
	
	public void makeSecreteKey(byte[] encodedPublicKey) throws InvalidKeyException, IllegalStateException, InvalidKeySpecException, NoSuchAlgorithmException {
		
		keyAgreement.doPhase(KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(encodedPublicKey)),true);
	
		this.keyDB = new KeyDB(keyAgreement.generateSecret());	
		
	}


	
	
}
