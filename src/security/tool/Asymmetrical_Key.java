package security.tool;

import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.CRC32;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.omg.CORBA.PUBLIC_MEMBER;

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
	  
	  public static KeyPair generate_KeyPair() throws NoSuchAlgorithmException{
		  
		  SecureRandom secureRandom = new SecureRandom();
		  KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
		  keyPairGenerator.initialize(KEYSIZE);	
		  KeyPair keyPair = keyPairGenerator.generateKeyPair();
		  return keyPair;
	  }
	  
	  
	  
	  public static byte[] encrypt_with_signature(String plaintext , Key signature_key, Key encrypt_key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		  

		  byte[] source_bytes = plaintext.getBytes();
		  return encrypt_with_signature(source_bytes, signature_key, encrypt_key); 
		  
		 // BASE64Encoder encoder = new BASE64Encoder();
		 // return encoder.encode(ciphertext_bytes);
	  }
	  
	  //加密发送的信息时请使用这个版本。
	  public static byte[] encrypt_with_signature(byte[] plaintext, Key signature_key, Key encrypt_key) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		  
		  //获取plaintext的SHA-1
		  
		  byte[] digest = get_SHA_1(plaintext);
		  
		  //对SHA-1进行加密，加密完是128位（有8位CRC）
		  byte[] signature = encrypt(digest,signature_key);
		  //对数据加密，前8位是CRC验证码
		  byte[] ciphertext = encrypt(plaintext, encrypt_key);
		  
		  return Byte_Connect.connect(signature, ciphertext);
	  }
	  
	  private static byte[] encrypt(byte[] plaintext , Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{  
		  
		  //计算CRC校验码
		  byte[] CRCcode = long2bytes(bytes_crc32(plaintext,0));
		  
		  //将CRC校验码连接到数据的头部，8byte
		  byte[] plaintext_with_CRC = Byte_Connect.connect(CRCcode, plaintext);
		  
		  //将连接后的数据加密
		  Cipher cipher = Cipher.getInstance(ALGORITHM);
		  cipher.init(Cipher.ENCRYPT_MODE, key);
		 
		  byte[] ciphertext_bytes = cipher.doFinal(plaintext_with_CRC);
		  return ciphertext_bytes;
	  }
	  
	  
	  //signature_key通常情况下为 发送者的公钥， decrypt_key 通常情况下为 接受者私钥
	  //如果签名或者数据CRC校验码不对，会抛出一个DataErrorException
	  public static byte[] decrypt_with_signature(byte[] ciphertext,Key signature_key, Key decrypt_key) throws Exception{
		  
		  byte[] signature = Arrays.copyOfRange(ciphertext, 0, 128);
		  byte[] ciphertext_segment = Arrays.copyOfRange(ciphertext, 128, ciphertext.length);
		  
		  byte[] plaintext = decrypt(ciphertext_segment, decrypt_key);
		  byte[] digest_received = decrypt(signature, signature_key);
          
		  byte[] digest = get_SHA_1(plaintext);
		  
		  if(!Arrays.equals(digest, digest_received))
		     throw new DataErrorException("dataerror");
		  
		  return plaintext; 
		 
	  } 
	  private static byte[] decrypt(byte[] ciphertext,Key key) throws Exception{
		  
		  //解密
		  Cipher cipher = Cipher.getInstance(ALGORITHM);
		  cipher.init(Cipher.DECRYPT_MODE, key);
		  byte[] plaintest_bytes_with_CRC = cipher.doFinal(ciphertext);
		  
		  //获得原CRC校验码
		  long CRC_Recieved = bytes2long(Arrays.copyOfRange(plaintest_bytes_with_CRC, 0 ,8));
		 
		  //获得收到数据的CRC校验码
		  
		  if(bytes_crc32(plaintest_bytes_with_CRC, 8)!=CRC_Recieved)
			  throw new DataErrorException("dataerror");
		  
		  return Arrays.copyOfRange(plaintest_bytes_with_CRC, 8, plaintest_bytes_with_CRC.length);
		 
	  }
	 
	  
	  private static byte[] long2bytes(long in){
		  ByteBuffer buffer = ByteBuffer.allocate(8); 
		  buffer.putLong(in);
		  return buffer.array();
	  }
	  
	  private static long bytes2long(byte[] in) {
		  ByteBuffer buffer = ByteBuffer.allocate(8); 
		  buffer.put(in,0,in.length);
		  buffer.flip();
		  return buffer.getLong();
	}
	  
	  //计算从offset开始到数组结束的CRC校验码
 	  private static long bytes_crc32(byte[] target,int offset){
 		  
 		  CRC32 crc32 =new CRC32();
 		 
 		  crc32.update(target,offset,target.length-offset);
 		  return crc32.getValue(); 
	  }

 	  private static byte[] get_SHA_1(byte[] in) throws NoSuchAlgorithmException{
 		  
 		  MessageDigest messageDigest = MessageDigest.getInstance("SHA-1"); 
		  messageDigest.update(in);
		  return messageDigest.digest();
 	  }
 	  
}
