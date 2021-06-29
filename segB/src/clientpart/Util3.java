package clientpart;

import common.*;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import server.Server;
import server.Util;

public class Util3 {
	private static String authAlias="clientauth";
	private static String cipherAlias="clientcipher";
	private static String signAlias="clientsign";
	private static String savePath = "/Users/lexy/Desktop/Clases/Seguridad/clientRecoveredFiles/";
	public static void start(final Socket client2, String idRegistro, String pass_wd) {
		// TODO Auto-generated method stub

		System.out.println("client start SEND ");
		new Thread() {
			public void run() {
				try {
					String op = "3"; 
					DataOutputStream out;

					out = new DataOutputStream(client2.getOutputStream());
					out.writeInt(op.getBytes().length);
					out.write(op.getBytes());
					out.flush();

					Certificate certificate = Client.getKeyStore().getCertificate(authAlias);
					byte [] certAuth= certificate.getEncoded();

					X509Certificate extra= (X509Certificate) certificate ;
					Principal idPropietario = extra.getIssuerDN();
					System.out.println("ID PROPIETARIO: "+ idPropietario.toString());

					out.writeInt(certAuth.length);
					out.write(certAuth);
					out.flush();
					out.writeInt(idRegistro.getBytes().length);
					out.write(idRegistro.getBytes());
					out.flush();

					ObjectInputStream input= new ObjectInputStream(client2.getInputStream());

					Response response = (Response) input.readObject();
					byte [] fileContent = null;
					byte [] SignRDContent;

					if(response.getError() == 0) {
						if(Validation.validateCert(response.getCert(), Client.getTrust())) {
							FileOutputStream file=new FileOutputStream(savePath+"file");

							if(response.getIsPrivate()) {
								try {
									file.write(
											fileContent = Encription.decriptFilePGP(response.getEncriptedKey(), response.getEncriptedFile(), response.getCipherParams(), pass_wd, cipherAlias, Client.getKeyStore()));

								} catch (Exception e) {
									System.out.println("Error desencriptando archivo: ");
									e.printStackTrace();
								}
							}else {
								fileContent = response.getNonEncriptedFile();
							}

							PrivateKey signkey = (PrivateKey) Client.getKeyStore().getKey(signAlias, pass_wd.toCharArray());
							byte [] firmadoc = Validation.signContent(fileContent, signkey);
							SignRDContent = getSignRDContent(response.getIdRegistro(),response.getSelloTemporal(), response.getIdPropietario(),fileContent, firmadoc);
							if(Validation.checkSign(response.getCert(),SignRDContent, response.getSigRD())) {
								file.write(fileContent);
								if(Client.checkHash(response.getIdRegistro(), fileContent)) {
									System.out.println("DOCUMENTO RECUPERADO CORRECTAMENTE");
								}else{
									System.out.println("DOCUMENTO ALTERADO POR EL REGISTRADOR");
								}
							}else {
								System.out.println("FALLO DE FIRMA DEL REGISTRADOR");
							}
							file.close();
						}else {
							System.out.println("Certificado del servidor no valido");
						}
					}else{
						System.out.println(response.getErrorMsg());
					}

					out.close();
					input.close();
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}.start();
	}

	public static byte[] getSignRDContent(int idRegistro, String selloTemporal,String idPropietario, byte[] nonEncriptedFile, byte[] firmaDoc) throws Exception {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write(idRegistro);
		outputStream.write(selloTemporal.getBytes());
		outputStream.write(idPropietario.toString().getBytes());
		outputStream.write(nonEncriptedFile);
		outputStream.write(firmaDoc);

		return outputStream.toByteArray();
	}
}
