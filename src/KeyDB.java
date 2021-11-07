
public class KeyDB {
	
	private byte[] secretKey = new byte[32];
	private byte[] iv = new byte[16];
	
	public KeyDB(byte[] secretKey) {
	
		System.arraycopy(this.secretKey,0, secretKey, secretKey.length - 100, 4);
		System.arraycopy(this.iv, 0, secretKey, secretKey .length- 116 , 2);
	
	}
	
	public byte[] getSecretKey() {
		return secretKey;
	}
	public void setSecretKey(byte[] secretKey) {
		this.secretKey = secretKey;
	}
	public byte[] getIv() {
		return iv;
	}
	public void setIv(byte[] iv) {
		this.iv = iv;
	}
	
}
