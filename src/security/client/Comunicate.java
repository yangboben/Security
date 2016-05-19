package security.client;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Comunicate {

	 public SSLContext sslContext;  
	 private int port = 8080;  
	 private String host = "172.17.0.124";  
	 public SSLSocket socket;  

	 public Comunicate() throws Exception {
		// TODO Auto-generated constructor stub
		 
		 sslContext = Auth.getSSLContext();  
         SSLSocketFactory factory = (SSLSocketFactory) sslContext.getSocketFactory();    
         socket = (SSLSocket)factory.createSocket();   
         String[] pwdsuits = socket.getSupportedCipherSuites();  
         //socket可以使用所有支持的加密套件  
         socket.setEnabledCipherSuites(pwdsuits);  
         //默认就是true  
         socket.setUseClientMode(true);  
           
         SocketAddress address = new InetSocketAddress(host, port);  
         socket.connect(address, 0);  
           
         Login_success listener = new Login_success();  
         socket.addHandshakeCompletedListener(listener);  
	}
	 
	public class Login_success implements HandshakeCompletedListener{

		@Override
		public void handshakeCompleted(HandshakeCompletedEvent event) {
			// TODO Auto-generated method stub
			
			System.out.println("login success");
		}
		
	}
}
