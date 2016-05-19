package security.tool;

import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.zip.CRC32;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


public class Asymmetrical_Key {
	
         static  Asymmetrical_Key rsa;
         private static final String ALGORITHM = "RSA";
         private static final int KEYSIZE = 1024;
         
	  public static Asymmetrical_Key getRsa(){
		  if(rsa ==null)
			  return new Asymmetrical_Key();
		  else 
			  return rsa;
		   
	  }
	  
	  public KeyPair generate_KeyPair() throws NoSuchAlgorithmException{
		  
		  SecureRandom secureRandom = new SecureRandom();
		  KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
		  keyPairGenerator.initialize(KEYSIZE);	
		  KeyPair keyPair = keyPairGenerator.generateKeyPair();
		  return keyPair;
	  }
	  
	  public byte[] encrypt(String plaintext , Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		  
		  byte[] source_bytes = plaintext.getBytes();
		  return encrypt(source_bytes, key); 
		  
		 // BASE64Encoder encoder = new BASE64Encoder();
		 // return encoder.encode(ciphertext_bytes);
	  }
	  
	  public byte[] encrypt(byte[] plaintext , Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{  
		  
		  Cipher cipher = Cipher.getInstance(ALGORITHM);
		  cipher.init(Cipher.ENCRYPT_MODE, key);
		  byte[] ciphertext_bytes = cipher.doFinal(plaintext);
		  return ciphertext_bytes;
	  }
	  
	  public String decrypt(String ciphertext,Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException{
		  Cipher cipher = Cipher.getInstance(ALGORITHM);
		  cipher.init(Cipher.DECRYPT_MODE, key);
		  BASE64Decoder decoder = new BASE64Decoder();
		  byte[] ciphertext_bytes = decoder.decodeBuffer(ciphertext);
		  byte[] plaintest_bytes = cipher.doFinal(ciphertext_bytes);
		  return new String(plaintest_bytes);
	  }
	 
	  
	  private byte[] long2bytes(long in){
		  ByteBuffer buffer = ByteBuffer.allocate(8); 
		  buffer.putLong(in);
		  return buffer.array();
	  }
	  
 	  private long bytes_crc32(byte[] target){
 		 CRC32 crc32 =new CRC32();
 		  crc32.update(target);
 		  return crc32.getValue(); 
	  }
 	  
}
