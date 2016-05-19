package security.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;

import com.sun.corba.se.spi.orbutil.fsm.Input;

import jdk.internal.org.objectweb.asm.tree.IntInsnNode;
import security.tool.*;
public class client {

	public static void main(String[] args) {
		    int start = 1;
//		try {
//			Comunicate comunicate = new Comunicate();
//			
//			DataOutputStream dataOutputStream = new DataOutputStream(comunicate.socket.getOutputStream());
//		   
//		   dataOutputStream.writeInt(666); 
//		   
//		   dataOutputStream.write("test".getBytes());
//		   
//		   DataInputStream dataInputStream = new DataInputStream(comunicate.socket.getInputStream());
//		  
//		   System.out.println(dataInputStream.readInt());
//		   
//		   
//		} catch (Exception e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} 
		    
		    int test=200;
		    byte i=3;
		    
		    test = (test & 0x00ffffff) | ( ( i&0x000000ff )<<24 & 0xff000000); 
		    test = (test & 0xffffff00) | 1;
		    byte t1 = (byte)((test& 0xff000000) >> 24);
		    System.out.println(Integer.toHexString(   test ));
	}
}
