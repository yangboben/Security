package security.client;

import java.io.FileInputStream;
import java.security.KeyStore;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class Auth {
	 private static SSLContext sslContext;  
	 public static SSLContext getSSLContext() throws Exception{  
	        
	        String protocol = "TLSV1";  
	        String clientTrustCerFile = "certification/clientTrust.jks";
	        String clientTrustCerPwd = "666666";
	          
	        //Trust Key Store  
	        KeyStore keyStore = KeyStore.getInstance("JKS");  
	        keyStore.load(new FileInputStream(clientTrustCerFile),   
	                clientTrustCerPwd.toCharArray());    
	              
	          
	        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");   
	        trustManagerFactory.init(keyStore);   
	        TrustManager[] tms = trustManagerFactory.getTrustManagers();  
	          
	        KeyManager[] kms = null;  
	        
	        sslContext = SSLContext.getInstance(protocol);  
	        sslContext.init(kms, tms, null); 
	        
	        return sslContext;  
	    }  
}
