package security.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;

import com.sun.corba.se.spi.orbutil.fsm.Input;

public class client {

	public static void main(String[] args) {
		    int start = 1;
		try {
			Comunicate comunicate = new Comunicate();
			
			DataOutputStream dataOutputStream = new DataOutputStream(comunicate.socket.getOutputStream());
		   
		   dataOutputStream.writeInt(666); 
		   
		   dataOutputStream.write("test".getBytes());
		   
		   DataInputStream dataInputStream = new DataInputStream(comunicate.socket.getInputStream());
		  
		   System.out.println(dataInputStream.readInt());
		   
		   
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
}
