package clientpart;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;

import javax.net.ssl.*;

public class Client {
	private static final String SERVER_ADDRESS = "localhost";
	private static final int SERVER_PORT = 443;

	private static final boolean OCSP_ENABLE = true; // Habilita ocsp stapling
	private static final boolean OCSP_CLIENT_SIDE_ENABLE = true; // Habilita ocsp client-side si ocsp stapling está
																	// habilitado

	private static TrustManager[] trustManagers;
	private static KeyManager[] keyManagers;

	public static void main(String[] args) throws IOException, KeyManagementException, UnrecoverableKeyException,
			KeyStoreException, SignatureException {

		if (args.length != 2) {
			System.out.println("Numero de parametros incorrecto, introduzca keyStore y trustStore");
			System.exit(0);
		}

		try {
			ocspProperties(OCSP_ENABLE, OCSP_CLIENT_SIDE_ENABLE);
			loadStores(args, "clientpass");
			DataOutputStream out = new DataOutputStream(connect().getOutputStream());
			String op = "1";
			out.writeInt(op.getBytes().length);
			out.write(op.getBytes());
			out.flush();
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static SSLSocket connect() throws KeyManagementException, UnknownHostException, IOException {

		SSLContext sc = null;
		try {
			sc = SSLContext.getInstance("TLS");

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		sc.init(keyManagers, trustManagers, null);

		SSLSocketFactory ssf = sc.getSocketFactory();
	

		SSLSocket client = (SSLSocket) ssf.createSocket(SERVER_ADDRESS, SERVER_PORT);
		System.out.println("\n****************************************************************************");
		System.out.println("**                                                                        **");
		System.out.println("**          Comienzo SSL Handshake -- Cliente y Server Autenticados       **");
		System.out.println("**                                                                        **");
		System.out.println("****************************************************************************\n");
		System.out.println("> OCSP habilitado: " + System.getProperty("com.sun.net.ssl.checkRevocation"));
		System.out.println("> OCSP Client-Side habilitado: " + Security.getProperty("ocsp.enable"));
		client.startHandshake();

		System.out.println("\n****************************************************************************");
		System.out.println("**                                                                        **");
		System.out.println("**                         Fin OK SSL Handshake                           **");
		System.out.println("**                                                                        **");
		System.out.println("****************************************************************************\n");

		return client;

	}

	private static boolean ocspProperties(boolean enabled, boolean clientSideEnabled) {
		System.setProperty("com.sun.net.ssl.checkRevocation", String.valueOf(enabled));
		Security.setProperty("ocsp.enable", String.valueOf(clientSideEnabled));
		return enabled;
	}

	private static void loadStores(String[] args, String passwd_key) throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException {

		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(new FileInputStream(args[0]), passwd_key.toCharArray());


		KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
		kmf.init(keyStore, passwd_key.toCharArray());

		keyManagers = kmf.getKeyManagers();

		KeyStore trustedStore = KeyStore.getInstance("JCEKS");

		trustedStore.load(new FileInputStream(args[1]), passwd_key.toCharArray());


		TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");


		tmf.init(trustedStore);
		trustManagers = tmf.getTrustManagers();
	}

}