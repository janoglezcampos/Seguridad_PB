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
	public static String signAlias= "clientsign";
	public static String serverCipherAlias= "servercipher";
	public static String clientCipherAlias= "clientcipher";

	public static void sendFile(final Socket clientSock, String name, String confidencialidad, String ubicacion,String passwd_key){
		System.out.println("Client start SEND ");
		try {
			if (confidencialidad.equals("PRIVADO")||confidencialidad.equals("PUBLICO")) {
				DataOutputStream out = new DataOutputStream(clientSock.getOutputStream());
				String op = "1";
				out.writeInt(op.getBytes().length);
				out.write(op.getBytes());
				out.flush();

				//Util.registrar("name", "confidencialidad", "C:\\Users\\usuario\\Desktop\\alamcenes/prueba.PNG");
				ArrayList<byte []> message = Util.generateMessage(passwd_key, ubicacion,confidencialidad);
				out.writeInt(confidencialidad.getBytes().length);
				out.write(confidencialidad.getBytes());
				//out.flush();
				out.writeInt(message.size());
				//out.flush();
				for(byte[] slice: message) {
					out.writeInt(slice.length);
					out.write(slice);
				}
				out.flush();

				ObjectInputStream response = new ObjectInputStream(clientSock.getInputStream());
				try {
					Response res = (Response) response.readObject();
					if(res.getError()!=0) {
						System.out.println("Error al guardar el archivo: " + res.getErrorMsg());
					}else{
						Certificate certFirma = res.getCert();
						Path path = Paths.get(ubicacion);
						byte[] fileContent = Files.readAllBytes(path);
						if(Validation.validateCert(certFirma, Client.getTrust())) {
							byte[] SignRDContent = getSignRDContent(res.getIdRegistro(),res.getSelloTemporal(), res.getIdPropietario(), fileContent, message.get(1));

							if(Validation.checkSign(certFirma, SignRDContent, res.getSigRD())) {
								Client.saveHash(res.getIdRegistro(), fileContent);
								System.out.println("Archivo guardado correctamente");
							}else{
								System.out.println("SigRD incorrecta");
								//SigRD incorrecta
							}
						}else{
							System.out.println("Certificado del servidor no válido");
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

	public static byte[] getSignRDContent(int idRegistro, String selloTemporal,String idPropietario, byte[] nonEncriptedFile, byte[] firmaDoc) throws Exception {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write(idRegistro);
		outputStream.write(selloTemporal.getBytes());
		outputStream.write(idPropietario.toString().getBytes());
		outputStream.write(nonEncriptedFile);
		outputStream.write(firmaDoc);

		return outputStream.toByteArray();
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
			PublicKey clavetrust = Client.getTrust().getCertificate(serverCipherAlias).getPublicKey();
			full = Encription.encript2sendPGP(full, fileContent, clavetrust);
		}else {
			full.add(fileContent);
		}
		//FIRMAMOS EL FICHERO NO ENCRIPTADO
		PrivateKey signkey = (PrivateKey) Client.getKeyStore().getKey(signAlias, clave);
		full.add(Validation.signContent(fileContent, signkey));

		//OBTENEMOS EL CERTFIRMA
		Certificate certiFirma = Client.getKeyStore().getCertificate(signAlias); 
		try {
			byte [] certibyte = certiFirma.getEncoded();
			full.add(certibyte);

		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		//OBTENEMOS CERTIFICADO DE CIFRADO 
		Certificate certiCifrado = Client.getKeyStore().getCertificate(clientCipherAlias);
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
