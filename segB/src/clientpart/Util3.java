package clientpart;

import common.*;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class Util3 {
	private static String authAlias = "clientauth";
	private static String cipherAlias = "clientcipher";
	private static String signAlias = "clientsign";
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
					byte[] certAuth = certificate.getEncoded();

					X509Certificate extra = (X509Certificate) certificate;
					Principal idPropietario = extra.getIssuerDN();
					System.out.println("ID PROPIETARIO: " + idPropietario.toString());

					out.writeInt(certAuth.length);
					out.write(certAuth);
					out.flush();
					out.writeInt(idRegistro.getBytes().length);
					out.write(idRegistro.getBytes());
					out.flush();

					ObjectInputStream input = new ObjectInputStream(client2.getInputStream());

					Response response = (Response) input.readObject();
					byte[] fileContent = null;
					byte[] SignRDContent;

					if (response.getError() == 0) {
						if (Validation.validateCert(response.getCert(), Client.getTrust())) {
							FileOutputStream file = new FileOutputStream(savePath + "file");

							if (response.getIsPrivate()) {
								try {
									file.write(fileContent = Encription.decriptFilePGP(response.getEncriptedKey(),
											response.getEncriptedFile(), response.getCipherParams(), pass_wd,
											cipherAlias, Client.getKeyStore()));

								} catch (Exception e) {
									System.out.println("Error desencriptando archivo: ");
									e.printStackTrace();
								}
							} else {
								fileContent = response.getNonEncriptedFile();
							}

							PrivateKey signkey = (PrivateKey) Client.getKeyStore().getKey(signAlias,
									pass_wd.toCharArray());

							// Si se comprueba
							byte[] firmadoc = Validation.signContent(fileContent, signkey);
							SignRDContent = Validation.getSignRDContent(response.getIdRegistro(),
									response.getSelloTemporal(), response.getIdPropietario(), fileContent, firmadoc);
							/*
							 * -> PROBLEMA CON EL ENUNCIADO!!
							 * 
							 * Entiendo que si un archivo es público, es porque queremos compartirlo con
							 * otros cliente pero... Si SigRD =
							 * SigR(idRegistro,selloTemporal,idPropietario,documento,firmaDoc) y firmaDoc =
							 * Sigpropietario(documento), y como la respuesta de recuperacion de archivo:
							 * (0,tipoConfidencialidad,idRegistro,idPropietario,selloTemporal,EPKC
							 * (K),EK(documento),SigRD,CertFirm ), no incluye firmaDoc, significa que para
							 * comprobar sigRD del lado del cliente para validarla, debes calcularla, pero
							 * es necesario dirmaDoc, y para calcular esta es necesaria la clave privada del
							 * cliente propietario que obviamente no tenemos, por lo tanto es imposible que
							 * se pueda validar SigRD desde un cliente que no sea el propietario original.
							 * 
							 * Además un cliente no tiene por qué conocer el hash de un archivo subido por
							 * otro cliente.
							 * 
							 * Para solucionarlo, aunque no es buena idea en un sistema real, se elimina la
							 * necesidad de validación de sigRD si el archivo es publico. En el caso del
							 * hash, en un sistema real tampoco se podría comprobar a menos que se enviase
							 * en la respuesta, por lo tanto tambien se ignora si es publico.
							 */

							if (Validation.checkSign(response.getCert(), SignRDContent, response.getSigRD())
									|| !response.getIsPrivate()) {
								file.write(fileContent);
								if (Client.checkHash(response.getIdRegistro(), fileContent)
										|| !response.getIsPrivate()) {
									System.out.println("DOCUMENTO RECUPERADO CORRECTAMENTE");
								} else {
									System.out.println("DOCUMENTO ALTERADO POR EL REGISTRADOR");
								}
							} else {
								System.out.println("FALLO DE FIRMA DEL REGISTRADOR");
							}

							file.close();
						} else {
							System.out.println("Certificado del servidor no valido");
						}
					} else {
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

}
