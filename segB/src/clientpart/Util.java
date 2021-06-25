package clientpart;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Files;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.TrustManager;


import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

public class Util {
	
	
	
	//public static SecretKey  keydef ;
	//public static byte [] encript;
	public static String signAlias= "clientsign";
	public static String serverCipherAlias= "servercipher";
	public static String clientCipherAlias= "clientcipher";
	public static ArrayList<byte[]> full= new ArrayList<byte[]> ();

	public static void startClientWorking(final Socket clientSock, String name, String confidencialidad, String ubicacion,String passwd_key){
		System.out.println("Client start SEND ");
		try {
			DataOutputStream out = new DataOutputStream(clientSock.getOutputStream());
			String op = "1";
			out.writeInt(op.getBytes().length);
			out.write(op.getBytes());
			out.flush();

			try {
				//Util.registrar("name", "confidencialidad", "C:\\Users\\usuario\\Desktop\\alamcenes/prueba.PNG");
				Util.registrar(passwd_key, ubicacion,confidencialidad);
			} catch (InvalidKeyException | UnrecoverableKeyException | NoSuchAlgorithmException
					| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | KeyStoreException
					| SignatureException e) {
				e.printStackTrace();
			}

			if (confidencialidad.equals("PRIVADO")) {

				System.out.println("Enviamos Tipo de confidencialidad:  "+ confidencialidad);
				out.writeInt(confidencialidad.getBytes().length);
				out.write(confidencialidad.getBytes());
				out.flush();
				System.out.println("CONFIDENCIALIDAD sent");

				System.out.println("Enviamos file encriptado de tamaño:  "+ full.get(1).length);
				out.writeInt(full.get(1).length);
				out.write(full.get(1));
				out.flush();
				System.out.println("FILE ENCRIPTADO sent");

				System.out.println("Enviamos parametros de tamaño:  "+ full.get(0).length);
				out.writeInt(full.get(0).length);
				out.write(full.get(0));
				out.flush();
				System.out.println("PARAMETROS sent");

				System.out.println("Enviamos clave encriptado de tamaño:  "+ full.get(2).length);
				out.writeInt(full.get(2).length);
				out.write(full.get(2));
				out.flush();
				System.out.println("CLAVE ENCRIPTADA sent");

				System.out.println("Enviamos FIRMA:  "+ full.get(3).length);
				out.writeInt(full.get(3).length);
				out.write(full.get(3));
				out.flush();
				System.out.println("FIRMA sent");

				System.out.println("Enviamos Nombre de documento:  "+ name);
				out.writeInt(name.getBytes().length);
				out.write(name.getBytes());
				out.flush();
				System.out.println("NOMBRE sent " +name.getBytes().length);

				System.out.println("Enviamos CERTFIRMA:  "+ full.get(4).length);
				out.writeInt(full.get(4).length);
				out.write(full.get(4));
				out.flush();
				System.out.println("CERTFIRMA sent");

				System.out.println("Enviamos CERTCIFRADO:  "+ full.get(5).length);
				out.writeInt(full.get(5).length);
				out.write(full.get(5));
				out.flush();
				System.out.println("CERTCIFRADO sent");  
			}
			else {
				System.out.println("Enviamos Tipo de confidencialidad:  "+ confidencialidad);
				out.writeInt(confidencialidad.getBytes().length);
				out.write(confidencialidad.getBytes());
				out.flush();
				System.out.println("CONFIDENCIALIDAD sent");

				System.out.println("Enviamos file de tamaño:  "+ full.get(0).length);
				out.writeInt(full.get(0).length);
				out.write(full.get(0));
				out.flush();
				System.out.println("FILE sent");

				System.out.println("Enviamos FIRMA:  "+ full.get(1).length);
				out.writeInt(full.get(1).length);
				out.write(full.get(1));
				out.flush();
				System.out.println("FIRMA sent");

				System.out.println("Enviamos Nombre de documento:  "+ name);
				out.writeInt(name.getBytes().length);
				out.write(name.getBytes());
				out.flush();
				System.out.println("NOMBRE sent " +name.getBytes().length);

				System.out.println("Enviamos CERTFIRMA:  "+ full.get(2).length);
				out.writeInt(full.get(2).length);
				out.write(full.get(2));
				out.flush();
				System.out.println("CERTFIRMA sent");  


				System.out.println("Enviamos CERTCIFRADO:  "+ full.get(3).length);
				out.writeInt(full.get(3).length);
				out.write(full.get(3));
				out.flush();
				System.out.println("CERTCIFRADO sent");  


			}

			BufferedReader input = new BufferedReader(new InputStreamReader(clientSock.getInputStream()));
			String received = input.readLine();
			System.out.println("Received : " + received);
			clientSock.close();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


	public static byte[] registrar(String passwd_key, String ubicacion, String confidencialidad) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, UnrecoverableKeyException, KeyStoreException, SignatureException {

		char[] clave = passwd_key.toCharArray();
		File data = new File(ubicacion);

		if (confidencialidad.equals("PRIVADO")) {
			//Generamos clave AES 128
			String algorithm= "AES";

			KeyGenerator kg= KeyGenerator.getInstance(algorithm);
			kg.init(128);
			SecretKey key= kg.generateKey();
			System.out.println("FORMATO clave de encriptado de info : "+key.getFormat());

			//Ciframos el fichero, con key sin cifrar
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte [] file_encriptado=cipher.doFinal(Files.readAllBytes(data.toPath()));
			System.out.println("PROVIDER ENCRIPTADO FICHERO: "+cipher.getProvider());
			//Se añade el mensaje la config usada en el cipher, codificada
			full.add(cipher.getParameters().getEncoded());
			full.add(file_encriptado);

			//OBTENEMOS CLAVE DEL TRUST 

			PublicKey clavetrust = Client.getTrust().getCertificate(serverCipherAlias).getPublicKey();

			//Ciframos la clave con la que se cifro el fichero
			cipher=Cipher.getInstance("RSA/ECB/PKCS1Padding");
			System.out.println("FORMATO clave del trust cliente: "+clavetrust.getFormat());

			cipher.init(Cipher.ENCRYPT_MODE, clavetrust);
			byte[] clave_encriptada= cipher.doFinal(key.getEncoded());


			full.add(clave_encriptada);

			System.out.println("TAMAÑO PAQUETE encriptado : "+ file_encriptado.length);

		}else {
			full.add(Files.readAllBytes(data.toPath()));

		}
		//FIRMAMOS EL FICHERO ENCRIPTADO
		PrivateKey clavekey = (PrivateKey) Client.getKeyStore().getKey(signAlias, clave);// tendria que ser asi con otra pareja de claves ??
		Signature firma =Signature.getInstance("MD5withRSA");
		firma.initSign(clavekey);
		firma.update(Files.readAllBytes(data.toPath()));
		byte[] bytesfirma= firma.sign();

		full.add(bytesfirma);

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


		System.out.println("TAMAÑO PAQUETE firmado: "+ bytesfirma.length);
		System.out.println("TAMAÑO PAQUETE sin firmar: "+ Files.readAllBytes(data.toPath()).length);

		return bytesfirma; // CAMBIAR POR VOID 
	}


}
