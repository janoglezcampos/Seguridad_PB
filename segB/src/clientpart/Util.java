package clientpart;

import common.*;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.ArrayList;

public class Util {
	public static final String CIPHER_ALIAS =Client.CIPHER_ALIAS;
	public static final String SIGN_ALIAS=Client.SIGN_ALIAS;
	public static final String AUTH_ALIAS=Client.AUTH_ALIAS;
	public static final String SERVER_CIPHER_ALIAS = Client.SERVER_CIPHER_ALIAS;

	public static void sendFile(final Socket clientSock, String confidencialidad, String ubicacion,String passwd_key){
		try {
			if (confidencialidad.equals("PRIVADO")||confidencialidad.equals("PUBLICO")) {
				
				DataOutputStream out = new DataOutputStream(clientSock.getOutputStream());
				String op = "1";
				out.writeInt(op.getBytes().length);
				out.write(op.getBytes());
				out.flush();

				ArrayList<byte []> message = Util.generateMessage(passwd_key, ubicacion,confidencialidad);
				out.writeInt(confidencialidad.getBytes().length);
				out.write(confidencialidad.getBytes());
				
				out.writeInt(message.size());
				
				for(byte[] slice: message) {
					out.writeInt(slice.length);
					out.write(slice);
				}
				out.flush();

				ObjectInputStream response = new ObjectInputStream(clientSock.getInputStream());
				try {
					Response res = (Response) response.readObject();
					if(res.getError()!=0) {
						System.out.println("\n!Error: " + res.getErrorMsg());
					}else{
						Certificate certFirma = res.getCert();
						Path path = Paths.get(ubicacion);
						byte[] fileContent = Files.readAllBytes(path);
						if(Validation.validateCert(certFirma, Client.getTrust())) {
							byte[] SignRDContent = Validation.getSignRDContent(res.getIdRegistro(),res.getSelloTemporal(), res.getIdPropietario(), fileContent, message.get(1));

							if(Validation.checkSign(certFirma, SignRDContent, res.getSigRD())) {
								Client.saveHash(res.getIdRegistro(), fileContent);
								System.out.println("Documento correctamente registrado con el numero con ID: " + res.getIdRegistro());
								Files.deleteIfExists(Paths.get(ubicacion));
							}else{
								System.out.println("\n!Error: " + "SigRD incorrecta");
								//SigRD incorrecta
							}
						}else{
							System.out.println("\n!Error: " + "Certificado del servidor no válido");
							//Cert no valido
						}
					}
				} catch (ClassNotFoundException e) {
					e.printStackTrace();
				}
				response.close();
				clientSock.close();

			} else {
				System.out.println("Error en el parametro de confidencialidad");
				clientSock.close();
				return;
			}
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
	
	/*
	 Operacion
	 PRIVADO:
		 Cofidencialidad
		 Archivo
		 Firma
		 Nombre de archivo
		 Certificado firma
		 Cerificado cifrado
	 PUBLICO:
		 Confidencialidad
		 Archivo
		 Firma
		 Nombre de documento
		 Certificado de firma
		 Cerificado de cifrado

		 Parametros
		 Clave
	 */

	public static ArrayList<byte[]> generateMessage(String passwd_key, String ubicacion, String confidencialidad) throws Exception {
		ArrayList<byte[]> full= new ArrayList<byte[]> ();
		char[] clave = passwd_key.toCharArray();

		Path path = Paths.get(ubicacion);
		byte[] fileContent = Files.readAllBytes(path);

		if (confidencialidad.equals("PRIVADO")) {
			PublicKey clavetrust = Client.getTrust().getCertificate(SERVER_CIPHER_ALIAS).getPublicKey();
			full.addAll(Encription.encript2sendPGP(fileContent, clavetrust));
		}else {
			full.add(fileContent);
		}
		//FIRMAMOS EL FICHERO NO ENCRIPTADO
		PrivateKey signkey = (PrivateKey) Client.getKeyStore().getKey(SIGN_ALIAS, clave);
		full.add(Validation.signContent(fileContent, signkey));

		//OBTENEMOS EL CERTFIRMA
		Certificate certiFirma = Client.getKeyStore().getCertificate(SIGN_ALIAS); 
		try {
			byte [] certibyte = certiFirma.getEncoded();
			full.add(certibyte);

		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		//OBTENEMOS CERTIFICADO DE CIFRADO 
		Certificate certiCifrado = Client.getKeyStore().getCertificate(CIPHER_ALIAS);
		try {
			byte [] certibyte2 = certiCifrado.getEncoded();
			full.add(certibyte2);


		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		full.add(path.getFileName().toString().getBytes());

		return full; // CAMBIAR POR VOID 
	}
}
