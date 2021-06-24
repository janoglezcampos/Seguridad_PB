package server;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;

import javax.net.ssl.*;



public class Server {

	private static TrustManager[] trustManagers;
	private static KeyManager[] keyManagers ;
	private static KeyStore trust;
	private static  KeyStore key;
	private static int contador=0;
	private static boolean ocspEnable = false;
	private static String serverAuthCert = "server (ca_cert)";

	public static int getContador() {
		return contador;
	}

	public static void setContador(int contadorArg) {
		contador = contadorArg;
	}

	public  static void main(String[] args) {
		System.out.println(System.getProperty("java.version"));
		try {
			if (args.length!=4){
				System.out.println("Número de parametros incorrecto, introduzca keyStore, trustStore, contraseñaKeyStore y algoritmoCifrado");
				System.exit(0);
			}
			System.out.println("INICIANDO CONEXION");
			start(args[0],args[1],args[2],args[3]);
		} catch (UnrecoverableKeyException | KeyManagementException | NoSuchAlgorithmException | CertificateException
				| KeyStoreException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


	}

	public static void start(String keyStorePath, String trustStorePath, String password, String chipherAlgoritm) throws IOException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, KeyStoreException, KeyManagementException {
		System.out.println("INICIANDO ALMACENES");
		store(keyStorePath,trustStorePath,password);
		int port=8080;


		SSLContext sc = SSLContext.getInstance("TLS");
		final X509KeyManager origKm = (X509KeyManager)keyManagers[0];
		X509KeyManager km = new CustomKeyManager(serverAuthCert, origKm);
		sc.init(new KeyManager[] { km }, trustManagers, null);

		SSLServerSocketFactory ssf = sc.getServerSocketFactory();
		ServerSocket serverSocket1 = ssf.createServerSocket(port);
		((SSLServerSocket)serverSocket1).setNeedClientAuth(true);
		System.out.println("Esperando conexión... (OCSP habilitado: "+ System.getProperty("jdk.tls.server.enableStatusRequestExtension") +")");

		while (true) {			
			Socket aClient = serverSocket1.accept();
			System.out.println("Client accepted");
			aClient.setSoLinger(true, 10000);

			DataInputStream input= new DataInputStream(aClient.getInputStream());
			System.out.println("Operación entrante");
			String operacion= new String (input.readNBytes(input.readInt()));
			//input.close();


			//Registrar documento
			if (operacion.equals("1")) {
				Util.startServerWorking(aClient,chipherAlgoritm,password);

				//input.close();
				//break;
			}
			//Listar documentos
			else if (operacion.equals("2")) {
				Util2.start(aClient);
			}
			//Recuperar documentos
			else if (operacion.equals("3")) {
				Util3.start(aClient, password);

			}
			else {
				System.out.println("Operación incorrecta");
				break;
			}
		}
	}

	public static void store(String keyStorePath, String trustStorePath, String passKeystore) throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, KeyStoreException {
		System.setProperty("jdk.tls.server.enableStatusRequestExtension", String.valueOf(ocspEnable));
		
		KeyStore keyStore;

		keyStore = KeyStore.getInstance("JCEKS");
		//keyStore.load(new FileInputStream("C:\\Users\\usuario\\Desktop\\alamcenes/serverkey.jks"),"serverpass".toCharArray());


		char[] clave = passKeystore.toCharArray();
		keyStore.load(new FileInputStream(keyStorePath),clave);

		//key=KeyStore.getInstance("JKS");
		//key.load(new FileInputStream(args),args3.toCharArray());;

		key = keyStore;

		//keyStore.deleteEntry("oo");
		//keyStore.deleteEntry("firma");

		System.out.println("keystore  tamaño "+key.size());
		System.out.println("key  tamaño "+keyStore.size());
		//Enumeration<String> alias =key.aliases();
		//String name=alias.nextElement();
		//System.out.println("Alias del 1 elemento: "+ name);
		//String name ="certauth";
		//System.out.println("CLAVE DEL KEY: "+ key.getKey(name,clave));

		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		//kmf.init(keyStore, "serverpass".toCharArray());
		kmf.init(keyStore, clave);
		
		
		keyManagers = kmf.getKeyManagers();

		KeyStore trustedStore = KeyStore.getInstance("JCEKS");
		//trustedStore.load(new FileInputStream("C:\\Users\\usuario\\Desktop\\alamcenes/serverTrustedCerts.jks"), "serverpass".toCharArray());
		trustedStore.load(new FileInputStream(trustStorePath), clave);  

		trust=trustedStore;
		System.out.println("Tamaño del trust  "+trust.size());
		//Enumeration<String> alias2 =trust.aliases();
		//String name2= alias2.nextElement();
		//System.out.println("Alias del 1 elemento: "+ name2);
		//System.out.println("CLAVE DEL TRUST: "+ trust.getCertificate(name2).getPublicKey());


		TrustManagerFactory tmf = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		tmf.init(trustedStore);

		trustManagers = tmf.getTrustManagers();

		//MISMA OPINION QUE EN EL CLIENT 
		System.setProperty("javax.net.ssl.keyStore", keyStorePath);
		System.setProperty("javax.net.ssl.keyStoreType",     "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword",passKeystore);


		System.setProperty("jdk.security.allowNonCaAnchor", "true" );
		System.setProperty("jdk.security.allowNonCaAnchor", "true" );

		System.setProperty("javax.net.ssl.trustStore", trustStorePath);
		System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", passKeystore);
		
	}
	public static KeyStore getTrust () {
		return trust;
	}

	public static KeyStore getKeyStore() {
		return key;
	}

	//Modificando chooseServerAlias podemos definir SIEMPRE que certificado enviamos, así podemos asegurar que la comprobación ocsp se hace
	//sobre el certificado que queremos
	static class CustomKeyManager implements X509KeyManager{
		
		private String certAlias;
		private X509KeyManager originalKm;
		
		public CustomKeyManager(String alias, X509KeyManager km) {
			this.certAlias = alias;
			this.originalKm = km;
		}
		
		@Override
		public String[] getClientAliases(String keyType, Principal[] issuers) {
			return originalKm.getClientAliases(keyType, issuers);
		}

		@Override
		public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
			return originalKm.chooseClientAlias(keyType, issuers, socket);
		}

		@Override
		public String[] getServerAliases(String keyType, Principal[] issuers) {
			return originalKm.getServerAliases(keyType, issuers);
		}

		@Override
		public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
			return certAlias;
		}

		@Override
		public X509Certificate[] getCertificateChain(String alias) {
			return originalKm.getCertificateChain(alias);
		}

		@Override
		public PrivateKey getPrivateKey(String alias) {
			return originalKm.getPrivateKey(alias);
		}
		
	}

}
