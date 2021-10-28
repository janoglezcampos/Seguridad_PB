package server;
package com.lexy.ocsp.server;


import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import javax.net.ssl.*;

public class Server {
	private static final String SERVER_KEYSTORE = "/home/lexy/Documents/clases/seg/Practica_B/stores/serverKeystore.jceks";
	private static final String SERVER_TRUSTSTORE = "/home/lexy/Documents/clases/seg/Practica_B/stores/serverTruststore.jceks";
	
	public static final String PASSWORD = "32004";
	
	public static final int SERVER_PORT = 5000;

	public static final String AUTHALIAS = "serverauth";

	private static final boolean OCSP_ENABLE = true;
	public static final boolean ID_FROM_SUBJECT = true;

	private static TrustManager[] trustManagers;
	private static KeyManager[] keyManagers;

	public static void main(String[] args) {
		System.out.println(System.getProperty("java.version"));
		try {
			System.out.println("INICIANDO CONEXION");
			start(SERVER_KEYSTORE, SERVER_TRUSTSTORE, PASSWORD);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	static class ServerParameters {
		boolean enabled = true;
		int cacheSize = 0;
		int cacheLifetime = 0;
		int respTimeout = 5000;
		String respUri = "http://localhost:9999";
		boolean respOverride = false;
		boolean ignoreExts = false;
		String[] protocols = new String[] { "TLSv1.2" };
		String[] ciphers = null;

		ServerParameters() {
		}
	}

	public static void start(String keyStorePath, String trustStorePath, String password)
			throws Exception {
		System.out.println("INICIANDO ALMACENES");
		ServerParameters servParams = new ServerParameters();

		// Set all the other operating parameters
		System.setProperty("jdk.tls.stapling.cacheSize", Integer.toString(servParams.cacheSize));
		System.setProperty("jdk.tls.stapling.cacheLifetime", Integer.toString(servParams.cacheLifetime));
		System.setProperty("jdk.tls.stapling.responseTimeout", Integer.toString(servParams.respTimeout));
		System.setProperty("jdk.tls.stapling.responderURI", servParams.respUri);
		System.setProperty("jdk.tls.stapling.responderOverride", Boolean.toString(servParams.respOverride));
		System.setProperty("jdk.tls.stapling.ignoreExtensions", Boolean.toString(servParams.ignoreExts));

		Security.setProperty("jdk.tls.disabledAlgorithms", "");
		store(keyStorePath, trustStorePath, password);

		SSLContext sc = SSLContext.getInstance("TLS");
		sc.init(keyManagers, trustManagers, null);

		// SSLServerSocketFactory sslssf = new CustomizedServerSocketFactory(sc,
		// servParams.protocols, servParams.ciphers);

		SSLServerSocketFactory ssf = sc.getServerSocketFactory();
		ServerSocket serverSocket1 = ssf.createServerSocket(SERVER_PORT);
		// ServerSocket serverSocket1 = (SSLServerSocket)
		// sslssf.createServerSocket(SERVER_PORT);
		((SSLServerSocket) serverSocket1)
				.setEnabledCipherSuites(((SSLServerSocket) serverSocket1).getSupportedCipherSuites());
		((SSLServerSocket) serverSocket1).setNeedClientAuth(true);
		// ((SSLServerSocket) serverSocket1).setEnabledProtocols(protocols);
		System.out.println("Esperando conexión... (OCSP habilitado: "
				+ System.getProperty("jdk.tls.server.enableStatusRequestExtension") + ")");

			try {
				Socket client = serverSocket1.accept();
				System.out.println(client.getRemoteSocketAddress().toString());
				System.out.println("Client accepted");

				DataInputStream input = new DataInputStream(client.getInputStream());
				System.out.println("Operación entrante");
				String operacion = new String(input.readNBytes(input.readInt()));
			} catch (Exception e) {
				System.out.println("Error ejecutando durante la comunicacion");
				e.printStackTrace();
			}
	}

	public static void store(String keyStorePath, String trustStorePath, String passKeystore)
			throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException,
			UnrecoverableKeyException, KeyStoreException {
		System.setProperty("jdk.tls.server.enableStatusRequestExtension", String.valueOf(OCSP_ENABLE));

		KeyStore keyStore;
		KeyStore trustedStore;

		char[] clave = passKeystore.toCharArray();

		keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(new FileInputStream(keyStorePath), clave);


		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keyStore, clave);

		keyManagers = kmf.getKeyManagers();

		trustedStore = KeyStore.getInstance("JCEKS");
		trustedStore.load(new FileInputStream(trustStorePath), clave);

		TrustManagerFactory tmf = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		tmf.init(trustedStore);

		trustManagers = tmf.getTrustManagers();

	}


}

