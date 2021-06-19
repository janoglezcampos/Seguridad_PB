package server;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;



public class server {

	static TrustManager[] trustManagers;
	static KeyManager[] keyManagers ;
    static KeyStore trust;
    static  KeyStore key;
    static int contador=0;

	
public static int getContador() {
		return contador;
	}

	public static void setContador(int contador) {
		server.contador = contador;
	}

public  static void main(String[] args) {
	
	try {
		if (args.length!=4){
			System.out.println("N�mero de parametros incorrecto, introduzca keyStore,trustStore, contrase�aKeyStore y algoritmoCifrado");
			System.exit(0);
		}
		System.out.println("INICIANDO ALMACENES");
		start(args[0],args[1],args[2],args[3]);
	} catch (UnrecoverableKeyException | KeyManagementException | NoSuchAlgorithmException | CertificateException
			| KeyStoreException | IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	

}

public static void start(String args, String args2, String args3, String args4) throws IOException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, KeyStoreException, KeyManagementException {
store(args,args2,args3);
int port=8080;
	

			SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(keyManagers, trustManagers, null);

			SSLServerSocketFactory ssf = sc.getServerSocketFactory();
			ServerSocket serverSocket1 = ssf.createServerSocket(port);
			
	while (true) {			
			Socket aClient = serverSocket1.accept();
            System.out.println("Client accepted");
            aClient.setSoLinger(true, 10000);
             
            DataInputStream input= new DataInputStream(aClient.getInputStream());
            System.out.println("Operaci�n entrante");
            String operacion= new String (input.readNBytes(input.readInt()));
            //input.close();
            
			
	
		if (operacion.equals("1")) {
				Util.startServerWorking(aClient,args4,args3);
				
				//input.close();
				//break;
		}
		else if (operacion.equals("2")) {
				Util2.start(aClient);
		}
		else if (operacion.equals("3")) {
			    Util3.start(aClient, args3);
			
		}
		else {
			System.out.println("Operaci�n incorrecta");
			break;
		}
	}
}

public static void store(String args, String args2, String args3) throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, KeyStoreException {
	
	KeyStore keyStore;

		keyStore = KeyStore.getInstance("JKS");
		//keyStore.load(new FileInputStream("C:\\Users\\usuario\\Desktop\\alamcenes/serverkey.jks"),"serverpass".toCharArray());
		keyStore.load(new FileInputStream(args),args3.toCharArray());
		
		//key=KeyStore.getInstance("JKS");
		//key.load(new FileInputStream(args),args3.toCharArray());;
		
		key =keyStore;
		
		//keyStore.deleteEntry("oo");
		//keyStore.deleteEntry("firma");
		
		System.out.println("keystore  tama�o "+key.size());
		System.out.println("key  tama�o "+keyStore.size());
		//Enumeration<String> alias =key.aliases();
		//String name=alias.nextElement();
		//System.out.println("Alias del 1 elemento: "+ name);
		//String name ="certauth";
		
		char[] clave = args3.toCharArray();
		//System.out.println("CLAVE DEL KEY: "+ key.getKey(name,clave));
		
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		//kmf.init(keyStore, "serverpass".toCharArray());
		kmf.init(keyStore, clave);
		 keyManagers = kmf.getKeyManagers();
		
		KeyStore trustedStore = KeyStore.getInstance("JKS");
		//trustedStore.load(new FileInputStream("C:\\Users\\usuario\\Desktop\\alamcenes/serverTrustedCerts.jks"), "serverpass".toCharArray());
		trustedStore.load(new FileInputStream(args2), clave);  //no deberia tener contra OJO 
		
		trust=trustedStore;
		System.out.println("Tama�o del trust  "+trust.size());
		//Enumeration<String> alias2 =trust.aliases();
		//String name2= alias2.nextElement();
		//System.out.println("Alias del 1 elemento: "+ name2);
		//System.out.println("CLAVE DEL TRUST: "+ trust.getCertificate(name2).getPublicKey());
		
		
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(trustedStore);

	    trustManagers = tmf.getTrustManagers();
		
	//MISMA OPINION QUE EN EL CLIENT 
	System.setProperty("javax.net.ssl.keyStore", args);
	System.setProperty("javax.net.ssl.keyStoreType",     "JKS");
	System.setProperty("javax.net.ssl.keyStorePassword",args3);
	
    
    System.setProperty("jdk.security.allowNonCaAnchor", "true" );
	
	System.setProperty("javax.net.ssl.trustStore", args2);
	System.setProperty("javax.net.ssl.trustStoreType",     "JKS");
	System.setProperty("javax.net.ssl.trustStorePassword", args3);
	
}
public static KeyStore getTrust () {
	return trust;
}

public static KeyStore getKeymanagers () {
	return key;
}

	
	
	
}
