package clientpart;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import javax.crypto.*;
import javax.net.ssl.*;


//Arguments:
// /Users/lexy/Desktop/Clases/Seguridad/almacenes/keystoreClient.jceks
// /Users/lexy/Desktop/Clases/Seguridad/almacenes/truststoreClient.jceks
public class Client {
	private static TrustManager[] trustManagers;
	private static KeyManager[] keyManagers ;
	private static KeyStore trust;
	private static KeyStore key;
	private static boolean ocspEnable = true; //Habilita ocsp stapling
	private static boolean ocspClientEnable = false; //Habilita ocsp client-side si ocsp stapling está habilitado

	private static String cipherAlias="clientcipher";
	private static String pass_wd="clientpass";
	
	private static String sentDatabase = "/Users/lexy/Desktop/Clases/Seguridad/sentDatabase.txt";

	public static void main(String[] args)throws IOException, KeyManagementException, UnrecoverableKeyException, KeyStoreException, SignatureException {
		System.out.println(System.getProperty("java.version"));

		if (args.length!=2) {
			System.out.println("Número de parametros incorrecto, introduzca keyStore y trustStore");
			System.exit(0);
		}

		try {
			start(args);
		} catch (Exception e) {
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

				//La clave que aqui se introduce es la de las claves, no la del keystore, en este caso es la misma
				Util.sendFile(conexion(),name,confidencialidad,ubicacion,passwd_key);

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
				System.out.println("Introduzca a contraseña del keyStore");
				String passwd_key3=reader.readLine();
				try {
					System.out.println("INICIANDO ALMACENES");
					store(args,passwd_key3);
				} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
						| IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				Util3.start(conexion(),idRegistro,passwd_key3);

				control=1;
				break;

			default: System.out.println("Debe sellecionar un número de operación válido");
			break;

			}
		}
	}

	public static SSLSocket conexion() throws KeyManagementException, UnknownHostException, IOException {

		int port=443;
		String[]   cipherSuites = null;
		String ip= "127.0.0.1";

		Security.setProperty("jdk.tls.disabledAlgorithms", "");

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
			if(cipherSuites[i].contains("NULL")) System.out.println (cipherSuites[i]);

		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in)); 
		System.out.println ("Introduzca la CypherSuite: (Pulsar ENTER para usar TLS_RSA_WITH_NULL_SHA256)");
		String value = reader.readLine().trim();
		//https://datatracker.ietf.org/doc/html/rfc4346#appendix-C
		//https://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunJSSEProvider
		//Queremos autenticación pero no cifrado!
		//TLS_RSA_WITH_NULL_SHA256
		if("".equals(value) || value.isEmpty()) {
			value = "TLS_RSA_WITH_NULL_SHA256";
		}

		String[] cipher = {value};

		System.out.println ("Usando: " + cipher[0]);
		InetAddress add = InetAddress.getByName("localhost");

		SSLSocket client = (SSLSocket) ssf.createSocket(ip, port, add, 5000);
		
		String[] protocols={"TLSv1.2"};
		client.setEnabledProtocols(protocols);
		client.setEnabledCipherSuites(cipher);
		System.out.println ("\n****** CypherSuites Habilitadas en el ssl socket **********");

		String[] cipherSuitesHabilSocket = client.getEnabledCipherSuites();
		for (int i=0; i<cipherSuitesHabilSocket.length; i++) 
			System.out.println (cipherSuitesHabilSocket[i]);

		System.out.println ("\n*************************************************************");	    
		System.out.println ("  Comienzo SSL Handshake -- Cliente y Server Autenticados");
		System.out.println ("*************************************************************\n");
		System.out.println ("OCSP habilitado: " + System.getProperty("com.sun.net.ssl.checkRevocation"));
		System.out.println ("OCSP Client-Side habilitado: " + Security.getProperty("ocsp.enable"));
		client.startHandshake();


		System.out.println ("\n*************************************************************");
		System.out.println ("Fin OK SSL Handshake");
		System.out.println ("*************************************************************\n");

		return client;

	}
	
	public static boolean ocspProperties(boolean enabled, boolean clientSideEnabled) {
		System.setProperty("com.sun.net.ssl.checkRevocation", String.valueOf(enabled));
		Security.setProperty("ocsp.enable", String.valueOf(clientSideEnabled));
		return enabled;
	}

	public static void store(String[] args, String passwd_key) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException {

		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		//System.out.println(passwd_key);
		keyStore.load(new FileInputStream(args[0]),passwd_key.toCharArray());

		key = keyStore;

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

		boolean revocationCheck = ocspProperties(ocspEnable, ocspClientEnable);

		if(revocationCheck) {
			try {
				CertPathBuilder certBuilder = CertPathBuilder.getInstance("PKIX");
				PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certBuilder.getRevocationChecker();
				revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
				//Los certificados incluyen el url
				//revocationChecker.setOcspResponder(new URI(ocspURI));

				PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustedStore, new X509CertSelector());
				//pkixParams.addCertPathChecker(revocationChecker);
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

		//System.setProperty("jdk.security.allowNonCaAnchor", "true" );

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

	public static void saveHash(int idRegistro, byte [] content) {
		BufferedWriter bw;
		try {
			MessageDigest shaDigest = MessageDigest.getInstance("SHA-512");
			shaDigest.update(content);
			byte [] hash = shaDigest.digest();
			bw = new BufferedWriter(new FileWriter(sentDatabase,true));
			PrintWriter out = new PrintWriter(bw);
			out.println(idRegistro+"//"+hashToString(hash));
			out.close();
		} catch (IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	public static boolean checkHash(int idRegistro, byte [] content) {
		BufferedReader reader;
		try {
			MessageDigest shaDigest = MessageDigest.getInstance("SHA-512");
			shaDigest.update(content);
			byte [] hash = shaDigest.digest();
			System.out.println("Checking hash: " + hashToString(hash));
			
			reader = new BufferedReader(new FileReader(sentDatabase));
			String line = reader.readLine();
			while (line != null) {
				String[] parts = line.split("//");
				if(parts[0].equals(String.valueOf(idRegistro))) {
					reader.close();
					return parts[1].equals(hashToString(hash));
				}
				line = reader.readLine();
			}
			reader.close();
		} catch (IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	private static String hashToString(byte[] hash) {
		StringBuilder sb = new StringBuilder();
	    for(int i=0; i< hash.length ;i++)
	    {
	        sb.append(Integer.toString((hash[i] & 0xff) + 0x100, 16).substring(1));
	    }
	    //return complete hash
	   return sb.toString();
	}

}