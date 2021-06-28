package server;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;

import javax.crypto.Cipher;
import javax.net.ssl.*;


//Arguments:
//Users/lexy/Desktop/Clases/Seguridad/almacenes/keystoreServidor.jceks
//Users/lexy/Desktop/Clases/Seguridad/almacenes/truststoreServidor.jceks
//serverpass
//RC2
public class Server {

	private static TrustManager[] trustManagers;
	private static KeyManager[] keyManagers ;
	private static KeyStore trust;
	private static KeyStore key;
	private static int contador=0;
	private static boolean ocspEnable = true;
	private static String serverAuthCert = "serverauth";
	
	private static PublicKey clientPublicKey;
	private static AlgorithmParameters localCipherParams; 
	
	public static void setLocalCipherParams(AlgorithmParameters params) {
		localCipherParams = params;
	}
	
	public static AlgorithmParameters getLocalCipherParams() {
		return localCipherParams;
	}
	
	public static void setClientPublicKey(PublicKey publicKey) {
		clientPublicKey = publicKey;
	}
	
	public static PublicKey getClientPublicKey() {
		return clientPublicKey;
	}
	
	public static int getContador() {
		return contador;
	}

	public static void incremetarContador() {
		contador = contador+1;
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
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


	}
	
    static class ServerParameters {
        boolean enabled = true;
        int cacheSize = 256;
        int cacheLifetime = 3600;
        int respTimeout = 5000;
        String respUri = "http://localhost:9999";
        boolean respOverride = true;
        boolean ignoreExts = false;
        String[] protocols = new String[]{ "TLSv1.2" };
        String[] ciphers = null;

        ServerParameters() { }
    }

    static class CustomizedServerSocketFactory extends SSLServerSocketFactory {
        final SSLContext sslc;
        final String[] protocols;
        final String[] cipherSuites;

        CustomizedServerSocketFactory(SSLContext ctx, String[] prots, String[] suites)
                throws GeneralSecurityException {
            super();
            sslc = (ctx != null) ? ctx : SSLContext.getDefault();
            protocols = prots;
            cipherSuites = suites;

            // Create the Trust Manager Factory using the PKIX variant
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        }

        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            ServerSocket sock =
                    sslc.getServerSocketFactory().createServerSocket(port);
            customizeSocket(sock);
            return sock;
        }

        @Override
        public ServerSocket createServerSocket(int port, int backlog)
                throws IOException {
            ServerSocket sock =
                    sslc.getServerSocketFactory().createServerSocket(port,
                            backlog);
            customizeSocket(sock);
            return sock;
        }

        @Override
        public ServerSocket createServerSocket(int port, int backlog,
                InetAddress ifAddress) throws IOException {
            ServerSocket sock =
                    sslc.getServerSocketFactory().createServerSocket(port,
                            backlog, ifAddress);
            customizeSocket(sock);
            return sock;
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return sslc.getDefaultSSLParameters().getCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return sslc.getSupportedSSLParameters().getCipherSuites();
        }

        private void customizeSocket(ServerSocket sock) {
            if (sock instanceof SSLServerSocket) {
                if (protocols != null) {
                    ((SSLServerSocket)sock).setEnabledProtocols(protocols);
                }
                if (cipherSuites != null) {
                    ((SSLServerSocket)sock).setEnabledCipherSuites(cipherSuites);
                }
            }
        }
    }
        

	public static void start(String keyStorePath, String trustStorePath, String password, String chipherAlgoritm) throws Exception {
		System.out.println("INICIANDO ALMACENES");
		ServerParameters servParams = new ServerParameters();
		
        System.setProperty("jdk.tls.server.enableStatusRequestExtension",
                Boolean.toString(servParams.enabled));

        // Set all the other operating parameters
        System.setProperty("jdk.tls.stapling.cacheSize",
                Integer.toString(servParams.cacheSize));
        System.setProperty("jdk.tls.stapling.cacheLifetime",
                Integer.toString(servParams.cacheLifetime));
        System.setProperty("jdk.tls.stapling.responseTimeout",
                Integer.toString(servParams.respTimeout));
        System.setProperty("jdk.tls.stapling.responderURI", servParams.respUri);
        System.setProperty("jdk.tls.stapling.responderOverride",
                Boolean.toString(servParams.respOverride));
        System.setProperty("jdk.tls.stapling.ignoreExtensions",
                Boolean.toString(servParams.ignoreExts));
		store(keyStorePath,trustStorePath,password);
		int port=443;


		SSLContext sc = SSLContext.getInstance("TLS");
		final X509KeyManager origKm = (X509KeyManager)keyManagers[0];
		X509KeyManager km = new CustomKeyManager(serverAuthCert, origKm);
		sc.init(new KeyManager[] { km }, trustManagers, null);
		
		SSLServerSocketFactory sslssf = new CustomizedServerSocketFactory(sc,
                servParams.protocols, servParams.ciphers);

		//SSLServerSocketFactory ssf = sc.getServerSocketFactory();
		//ServerSocket serverSocket1 = ssf.createServerSocket(port);
		ServerSocket serverSocket1 = (SSLServerSocket) sslssf.createServerSocket(port);
		((SSLServerSocket)serverSocket1).setNeedClientAuth(true);
		//((SSLServerSocket) serverSocket1).setEnabledProtocols(protocols);
		System.out.println("Esperando conexión... (OCSP habilitado: "+ System.getProperty("jdk.tls.server.enableStatusRequestExtension") +")");

		while (true) {			
			Socket aClient = serverSocket1.accept();
			System.out.println(aClient.getRemoteSocketAddress().toString());
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
				Util3.start(aClient, chipherAlgoritm, password);

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
