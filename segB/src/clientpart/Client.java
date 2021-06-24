package clientpart;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import javax.crypto.*;
import javax.net.ssl.*;



public class Client {

	private static TrustManager[] trustManagers;
	private static KeyManager[] keyManagers ;
	private static KeyStore trust;
	private static KeyStore key;
	private static String ocspURI = "http://127.0.0.1:9997";
	private static boolean ocspStaplingEnable = false;
	private static boolean ocspClientEnable = true;

	public static void main(String[] args)throws IOException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, SignatureException {
		System.out.println(System.getProperty("java.version"));

		try {

			if (args.length!=2) {
				System.out.println("Número de parametros incorrecto, introduzca keyStore y trustStore");
				System.exit(0);
			}

			try {
				store(args,"clientpass");
				conexion();
				start(args);
			} catch (KeyManagementException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException
					| SignatureException | IOException | CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		} catch (InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


	}

	public static void start(String [] args) throws IOException, KeyManagementException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, SignatureException {


		System.out.println("Selecione la operación a realizar (teclee el número): "
				+ "\n 1.Registrar documento (nombreDoc, tipoConfidencialidad, E_PKS(K), E_K(documento), firmaDoc, CertFirma_C, CertCifrado_C) "
				+ "\n 2.Listar (Tipo, CertAuth_C) "
				+ "\n 3.Recuperar documento (CertAuth_C, idRegistro)");

		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));     
		int control=0;

		while(control==0) {
			String answer = reader.readLine();
			switch (answer) {
			case "1": 
				System.out.println("Introduzca el nombre del documento: ");
				String name = reader.readLine();
				System.out.println("Introduzca el tipo de confidencialidad (PRIVADO o PUBLICO)");
				String confidencialidad= reader.readLine();
				System.out.println("Introduzca la ubicación del archivo completa: ");
				String ubicacion =reader.readLine();
				System.out.println("Introduzca a contraseña del keyStore");
				String passwd_key=reader.readLine();
				try {
					System.out.println("INICIANDO ALMACENES");
					store(args,passwd_key);
				} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
						| IOException e) {
					e.printStackTrace();
					System.exit(0);
				}


				Util.startClientWorking(conexion(),name,confidencialidad,ubicacion,passwd_key);

				control =1;
				break;
			case "2": 
				System.out.println("Introduzca el tipo de confidencialidad (PRIV o PUB)");
				String confidencialidad2= reader.readLine();
				System.out.println("Introduzca el CertAuth");
				String cert_listar= reader.readLine();
				System.out.println("Introduzca a contraseña del keyStore");
				String passwd_key2=reader.readLine();
				try {
					System.out.println("INICIANDO ALMACENES");
					store(args,passwd_key2);
				} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
						| IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				Util2.start(conexion(),confidencialidad2,cert_listar);


				control=1;
				break;
			case "3": 

				System.out.println("Introduzca el idRegistro ");
				String idRegistro= reader.readLine();
				System.out.println("Introduzca el CertAuth");
				String cert_rec= reader.readLine();
				System.out.println("Introduzca a contrase�a del keyStore");
				String passwd_key3=reader.readLine();
				try {
					System.out.println("INICIANDO ALMACENES");
					store(args,passwd_key3);
				} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
						| IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				Util3.start(conexion(),idRegistro,cert_rec);





				control=1;
				break;

			default: System.out.println("Debe sellecionar un número de operación válido");
			break;

			}
		}


	}

	public static SSLSocket conexion() throws KeyManagementException, UnknownHostException, IOException {

		int port=8080;
		String[]   cipherSuites = null;
		String ip= "127.0.0.1";
		

		SSLContext sc = null;
		try {
			sc = SSLContext.getInstance("TLS");
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		sc.init(keyManagers, trustManagers, null);

		SSLSocketFactory ssf = sc.getSocketFactory();

		System.out.println ("******** CypherSuites Disponibles **********");
		cipherSuites = ssf.getSupportedCipherSuites();
		for (int i=0; i<cipherSuites.length; i++) 
			System.out.println (cipherSuites[i]);


		System.out.println ("****** CypherSuites Habilitadas por defecto **********");
		String[] cipherSuitesDef = ssf.getDefaultCipherSuites();
		for (int i=0; i<cipherSuitesDef.length; i++) 
			System.out.println (cipherSuitesDef[i]);


		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in)); 
		System.out.println ("Introduzca la CypherSuite: ");
		String [] cipher= {reader.readLine()};

		System.out.println ("AÑADIENDO: " + cipher[0]);

		SSLSocket client = (SSLSocket) ssf.createSocket(ip, port);

		client.setEnabledCipherSuites(cipher);

		System.out.println ("****** CypherSuites Habilitadas en el ssl socket **********");

		String[] cipherSuitesHabilSocket = client.getEnabledCipherSuites();
		for (int i=0; i<cipherSuitesHabilSocket.length; i++) 
			System.out.println (cipherSuitesHabilSocket[i]);

		System.out.println ("\n*************************************************************");	    
		System.out.println ("  Comienzo SSL Handshake -- Cliente y Server Autenticados");
		System.out.println ("*************************************************************");	    
		System.out.println (Security.getProperty("ocsp.enable"));
		client.startHandshake();


		System.out.println ("\n*************************************************************");
		System.out.println ("Fin OK SSL Handshake");
		System.out.println ("\n*************************************************************");

		return client;

	}

	public static void store(String[] args, String passwd_key) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException {

		if(ocspClientEnable) {
			System.setProperty("com.sun.net.ssl.checkRevocation",        "true");
			Security.setProperty("ocsp.enable",                            "true");
		}
		
		if(ocspStaplingEnable) {
			Security.setProperty("ocsp.enable", "false");
			System.setProperty("com.sun.net.ssl.checkRevocation", 		"true");
			System.setProperty("jdk.tls.client.enableStatusRequestExtension", "true");
		}
		
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		//System.out.println(passwd_key);
		keyStore.load(new FileInputStream(args[0]),passwd_key.toCharArray());

		key=keyStore;

		//keyStore.deleteEntry("cifradoc");
		//keyStore.deleteEntry("firmac");


		System.out.println("Keystore de tamaño "+key.size());

		//String name = "auth";	

		//String password=passwd_key;
		//char[] clave = password.toCharArray();
		//System.out.println("CLAVE DEL KEY: "+ key.getKey(name,clave));

		KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
		//System.out.println("prube "+KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keyStore, passwd_key.toCharArray());


		keyManagers = kmf.getKeyManagers();

		KeyStore trustedStore = KeyStore.getInstance("JCEKS");
		//trustedStore.load(new FileInputStream("C:\\Users\\usuario\\Desktop\\alamcenes/clientTrustedCerts.jks"), "clientpass".toCharArray());
		trustedStore.load(new FileInputStream(args[1]), passwd_key.toCharArray()); //supuestamente no hay que poner contrase�a es la misma pero no se deberia i dont know 
		trust=trustedStore;
		System.out.println("Tamaño del trust  "+trust.size());

		TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
		
		if(ocspClientEnable || ocspStaplingEnable) {
			try {
				CertPathBuilder certBuilder = CertPathBuilder.getInstance("PKIX");
				PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certBuilder.getRevocationChecker();
				revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
				//Los certificados incluyen el url
				//revocationChecker.setOcspResponder(new URI(ocspURI));
				
				PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustedStore, new X509CertSelector());
				pkixParams.addCertPathChecker(revocationChecker);
				pkixParams.setRevocationEnabled(true);
				ManagerFactoryParameters mfp =
		                new CertPathTrustManagerParameters(pkixParams);
				tmf.init(mfp);
			}catch(Exception e) {
				System.out.println("Exception on OCSP setup:" + e);
				System.exit(0);
			}
		}else {
			tmf.init(trustedStore);
		}
		
		trustManagers = tmf.getTrustManagers();

		System.setProperty("javax.net.ssl.keyStore", args[0]);
		System.setProperty("javax.net.ssl.keyStoreType",     "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", passwd_key);

		System.setProperty("jdk.security.allowNonCaAnchor", "true" );

		System.setProperty("javax.net.ssl.trustStore", args[1]);
		System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", passwd_key);
		

	}

	public static KeyStore getTrust () {
		return trust;
	}

	public static KeyStore getKeyStore () {
		return key;
	}




}