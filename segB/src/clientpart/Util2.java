package clientpart;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLSocket;

public class Util2 {

	private static String authAlias="clientAuth";
	public static void start(final Socket client2, String confidencialidad2, String cert_listar) {
		// TODO Auto-generated method stub

		System.out.println("client start SEND ");
		new Thread() {
			public void run() {
				try { 
					String op = "2"; 
					DataOutputStream out;

					out = new DataOutputStream(client2.getOutputStream());
					out.writeInt(op.getBytes().length);
					out.write(op.getBytes());
					out.flush();
					
					Certificate certificate = Client.getKeyStore().getCertificate(authAlias);
					byte [] certFirma= certificate.getEncoded();

					X509Certificate extra= (X509Certificate) certificate ;
					Principal idPropietario = extra.getIssuerDN();
					//System.out.println("ID PROPIETARIO: "+ idPropietario.toString());

					out.writeInt(idPropietario.toString().getBytes().length);
					out.write(idPropietario.toString().getBytes());
					out.flush();
					out.writeInt(confidencialidad2.getBytes().length);
					out.write(confidencialidad2.getBytes());
					out.flush();

					BufferedReader input = new BufferedReader(new InputStreamReader(client2.getInputStream()));
					String received = input.readLine();
					System.out.println("ID PROPIETARIO : "+"\n" + received);
					received = input.readLine();
					System.out.println("ID REGISTRO : "+"\n" + received);
					received = input.readLine();
					System.out.println("SELLO TEMPORAL : "+"\n" + received);
					received = input.readLine();
					System.out.println("NOMBRE DEL DOCUMENTO: "+"\n" + received);

					input.close();
					out.close();

				} catch (IOException | CertificateException | KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}.start();








	}

}
