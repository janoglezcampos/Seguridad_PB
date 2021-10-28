package server;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import javax.net.ssl.*;

public class Server {
	public static final int SERVER_PORT = 443;

	public static final String AUTHALIAS = "serverauth";

	private static final boolean OCSP_ENABLE = false;
	public static final boolean ID_FROM_SUBJECT = true;

	private static TrustManager[] trustManagers;
	private static KeyManager[] keyManagers;

	public static void main(String[] args) {
		System.out.println(System.getProperty("java.version"));
		try {
			if (args.length != 4) {
				System.out.println(
						"Número de parametros incorrecto, introduzca keyStore, trustStore, contraseñaKeyStore y algoritmoCifrado");
				System.exit(0);
			}

			System.out.println("INICIANDO CONEXION");
			start(args[0], args[1], args[2], args[3]);
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

	public static void start(String keyStorePath, String trustStorePath, String password, String chipherAlgoritm)
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
		final X509KeyManager origKm = (X509KeyManager) keyManagers[0];
		X509KeyManager km = new CustomKeyManager(AUTHALIAS, origKm);
		sc.init(new KeyManager[] { km }, trustManagers, null);

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
				// input.close();
				switch (operacion) {
				case "1":
					break;
				case "2":
					break;
				case "3":
					break;
				default:
					System.out.println("Operación desconocida");
					break;
				}
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

	// Modificando CustomKeyManager podemos definir SIEMPRE que certificado
	// enviamos, así podemos asegurar que la comprobación ocsp se hace
	// sobre el certificado que queremos
	static class CustomKeyManager implements X509KeyManager {

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
