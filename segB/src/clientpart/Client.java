package clientpart;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;

import javax.net.ssl.*;

public class Client {
	private static final String SERVER_ADDRESS = "localhost";
	private static final int SERVER_PORT = 443;

	private static final boolean OCSP_ENABLE = false; // Habilita ocsp stapling
	private static final boolean OCSP_CLIENT_SIDE_ENABLE = false; // Habilita ocsp client-side si ocsp stapling está
																	// habilitado
	public static final boolean CHECK_SIGN_IF_PUBLIC = true;
	
	public static final String CIPHER_ALIAS = "clientcipher";
	public static final String SIGN_ALIAS = "clientsign";
	public static final String AUTH_ALIAS = "clientauth";
	public static final String SERVER_CIPHER_ALIAS = "servercipher";

	private static final String HASH_DATABASE = "/Users/lexy/Desktop/Clases/Seguridad/sentDatabase.txt";
	public static final String SAVE_PATH = "/Users/lexy/Desktop/Clases/Seguridad/clientRecoveredFiles/";

	private static TrustManager[] trustManagers;
	private static KeyManager[] keyManagers;
	private static KeyStore trust;
	private static KeyStore key;

	public static void main(String[] args) throws IOException, KeyManagementException, UnrecoverableKeyException,
			KeyStoreException, SignatureException {
		System.out.println(System.getProperty("java.version"));

		if (args.length != 2) {
			System.out.println("Numero de parametros incorrecto, introduzca keyStore y trustStore");
			System.exit(0);
		}

		try {
			start(args);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void start(String[] args) throws Exception {
		System.out.println("\n****************************************************************************");
		System.out.println("**                                                                        **");
		System.out.println("**    Terminal de acceso al sistema de almacenamiento de archivos seguro  **");
		System.out.println("**                                                                        **");
		System.out.println("****************************************************************************\n");
		System.out.println("Selecione la operación a realizar (teclee el número): " + "\n 1.Registrar un documentos."
				+ "\n 2.Listar documentos." + "\n 3.Recuperar documento.");

		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		int control = 0;

		while (control == 0) {
			String answer = reader.readLine();
			switch (answer) {
			case "1":
				System.out.println("\n> Introduzca la ubicación del archivo completa:");
				String ubicacion = reader.readLine();
				String confidencialidad;
				do {
					System.out.println("\n> Introduzca el tipo de confidencialidad (PRIVADO o PUBLICO):");
					confidencialidad = reader.readLine();
				} while (!(confidencialidad.equals("PRIVADO") || confidencialidad.equals("PUBLICO")));
				System.out.println("\n> Introduzca la contraseña del keyStore:");
				String passwd_key = reader.readLine();
				try {
					loadStores(args, passwd_key);
					Util.sendFile(conexion(), confidencialidad, ubicacion, passwd_key);
				} catch (Exception e) {
					e.printStackTrace();
				}
				control = 1;
				break;
			case "2":
				do {
					System.out.println("\n> Introduzca el tipo de confidencialidad (PRIV o PUB):");
					confidencialidad = reader.readLine();
				} while (!(confidencialidad.equals("PRIV") || confidencialidad.equals("PUB")));

				System.out.println("\n> Introduzca a contraseña del keyStore:");
				String passwd_key2 = reader.readLine();
				try {
					loadStores(args, passwd_key2);
					Util2.start(conexion(), confidencialidad);
				} catch (Exception e) {
					e.printStackTrace();
				}
				control = 1;
				break;
			case "3":

				System.out.println("\n> Introduzca el idRegistro: ");
				String idRegistro = reader.readLine();
				// Es necesario? Creo que no
				System.out.println("\n> Introduzca a contraseña del keyStore");
				String passwd_key3 = reader.readLine();
				try {
					loadStores(args, passwd_key3);

					Util3.start(conexion(), idRegistro, passwd_key3);
				} catch (Exception e) {
					e.printStackTrace();
				}
				control = 1;
				break;

			default:
				System.out.println("\nDebe selecionar un número de operación válido");
				break;

			}
		}
	}

	private static SSLSocket conexion() throws KeyManagementException, UnknownHostException, IOException {
		String[] cipherSuites = null;

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
		System.out.println("\n****************************************************************************");
		System.out.println("**                                                                        **");
		System.out.println("**                          CypherSuites Disponibles                      **");
		System.out.println("**                                                                        **");
		System.out.println("****************************************************************************\n");
		System.out.println("\n******** CypherSuites Disponibles **********\n");
		cipherSuites = ssf.getSupportedCipherSuites();
		for (int i = 0; i < cipherSuites.length; i++)
			if (cipherSuites[i].contains("NULL"))
				System.out.println("* " + cipherSuites[i]);

		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("\n> Introduzca la CypherSuite: (Pulsar ENTER para usar TLS_RSA_WITH_NULL_SHA256)");
		String value = reader.readLine().trim();
		// https://datatracker.ietf.org/doc/html/rfc4346#appendix-C
		// https://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunJSSEProvider
		// Queremos autenticación pero no cifrado!
		// TLS_RSA_WITH_NULL_SHA256
		if ("".equals(value) || value.isEmpty()) {
			value = "TLS_RSA_WITH_NULL_SHA256";
		}

		String[] cipher = { value };

		SSLSocket client = (SSLSocket) ssf.createSocket(SERVER_ADDRESS, SERVER_PORT);

		String[] protocols = { "TLSv1.2" };
		client.setEnabledProtocols(protocols);
		client.setEnabledCipherSuites(cipher);
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

		key = keyStore;

		KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
		kmf.init(keyStore, passwd_key.toCharArray());

		keyManagers = kmf.getKeyManagers();

		KeyStore trustedStore = KeyStore.getInstance("JCEKS");

		trustedStore.load(new FileInputStream(args[1]), passwd_key.toCharArray());

		trust = trustedStore;

		TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");

		ocspProperties(OCSP_ENABLE, OCSP_CLIENT_SIDE_ENABLE);

		tmf.init(trustedStore);
		trustManagers = tmf.getTrustManagers();
	}

	public static KeyStore getTrust() {
		return trust;
	}

	public static KeyStore getKeyStore() {
		return key;
	}

	// Sobrescribir entrada si el idRegistro se repite, si solo se añade y se añadio
	// otro anteriormente, dara error
	public static void saveHash(int idRegistro, byte[] content) {
		BufferedWriter bw;
		try {
			MessageDigest shaDigest = MessageDigest.getInstance("SHA-512");
			shaDigest.update(content);
			byte[] hash = shaDigest.digest();
			bw = new BufferedWriter(new FileWriter(HASH_DATABASE, true));
			PrintWriter out = new PrintWriter(bw);
			out.println(idRegistro + "//" + hashToString(hash));
			out.close();
		} catch (IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	public static boolean checkHash(int idRegistro, byte[] content) {
		BufferedReader reader;
		try {
			MessageDigest shaDigest = MessageDigest.getInstance("SHA-512");
			shaDigest.update(content);
			byte[] hash = shaDigest.digest();
			System.out.println("Checking hash: " + hashToString(hash));

			reader = new BufferedReader(new FileReader(HASH_DATABASE));
			String line = reader.readLine();
			while (line != null) {
				String[] parts = line.split("//");
				if (parts[0].equals(String.valueOf(idRegistro))) {
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
		for (int i = 0; i < hash.length; i++) {
			sb.append(Integer.toString((hash[i] & 0xff) + 0x100, 16).substring(1));
		}
		// return complete hash
		return sb.toString();
	}

}