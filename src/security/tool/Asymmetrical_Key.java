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
	  
	  //���ܷ��͵���Ϣʱ��ʹ������汾��
	  public static byte[] encrypt_with_signature(byte[] plaintext, Key signature_key, Key encrypt_key) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		  
		  //��ȡplaintext��SHA-1
		  
		  byte[] digest = get_SHA_1(plaintext);
		  
		  //��SHA-1���м��ܣ���������128λ����8λCRC��
		  byte[] signature = encrypt(digest,signature_key);
		  //�����ݼ��ܣ�ǰ8λ��CRC��֤��
		  byte[] ciphertext = encrypt(plaintext, encrypt_key);
		  
		  return Byte_Connect.connect(signature, ciphertext);
	  }
	  
	  private static byte[] encrypt(byte[] plaintext , Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{  
		  
		  //����CRCУ����
		  byte[] CRCcode = long2bytes(bytes_crc32(plaintext,0));
		  
		  //��CRCУ�������ӵ����ݵ�ͷ����8byte
		  byte[] plaintext_with_CRC = Byte_Connect.connect(CRCcode, plaintext);
		  
		  //�����Ӻ�����ݼ���
		  Cipher cipher = Cipher.getInstance(ALGORITHM);
		  cipher.init(Cipher.ENCRYPT_MODE, key);
		 
		  byte[] ciphertext_bytes = cipher.doFinal(plaintext_with_CRC);
		  return ciphertext_bytes;
	  }
	  
	  
	  //signature_keyͨ�������Ϊ �����ߵĹ�Կ�� decrypt_key ͨ�������Ϊ ������˽Կ
	  //���ǩ����������CRCУ���벻�ԣ����׳�һ��DataErrorException
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
		  
		  //����
		  Cipher cipher = Cipher.getInstance(ALGORITHM);
		  cipher.init(Cipher.DECRYPT_MODE, key);
		  byte[] plaintest_bytes_with_CRC = cipher.doFinal(ciphertext);
		  
		  //���ԭCRCУ����
		  long CRC_Recieved = bytes2long(Arrays.copyOfRange(plaintest_bytes_with_CRC, 0 ,8));
		 
		  //����յ����ݵ�CRCУ����
		  
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
	  
	  //�����offset��ʼ�����������CRCУ����
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
