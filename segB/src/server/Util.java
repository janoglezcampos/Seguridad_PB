package server;

import common.*;

import java.io.*;
import java.net.Socket;
import java.security.KeyStore.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import clientpart.Client;



public class Util {
	//byte [] recv;
	//static byte [] array;
	//static ArrayList <Byte>  datos = new ArrayList <Byte>();
	private static ArrayList <String> privado = new ArrayList <String>();
	private static ArrayList <String> publico = new ArrayList <String>();
	private static String cipherAlias ="serverCipher";
	private static String signAlias="serverSign";
	private static String secretKeyAlias = "dataenckey";
	private static String savePath="/Users/lexy/Desktop/Clases/Seguridad/serverSavedFiles/";

	public static ArrayList<String> getPrivado() {
		return privado;
	}

	public static void setPrivado(ArrayList<String> privado) {
		Util.privado = privado;
	}

	public static ArrayList<String> getPublico() {
		return publico;
	}

	public static void setPublico(ArrayList<String> publico) {
		Util.publico = publico;
	}
	
	public static void receiveFile(final Socket aClient, String algoritmo, String contrasenha) {
		new Thread() {
			public void run() {
				try {
					ArrayList <byte []> full = new ArrayList <byte[]>();
					full.clear();
					char[] clave = contrasenha.toCharArray();
					DataInputStream input= new DataInputStream(aClient.getInputStream());
					System.out.println("Input entrante");
					String confidencialidad =new String (input.readNBytes(input.readInt()));
					Boolean isPrivate = confidencialidad.equals("PRIVADO");
					System.out.println("Confidencialidad  "+confidencialidad);
					int listSize=input.readInt();
					
					for(int i=0; i<listSize-2; i++) {
						full.add(input.readNBytes(input.readInt()));
					}
					byte[] desencriptado;
					if (isPrivate) {
						desencriptado = Encription.decriptFilePGP(full.get(2), full.get(0), full.get(1), contrasenha, cipherAlias, Server.getKeyStore());

					} else {
						desencriptado=full.get(0);
					}

					byte[] sign = (isPrivate) ? full.get(3) : full.get(1);
					byte[] cerFirma = (isPrivate) ? full.get(4) : full.get(2);


					CertificateFactory cf   = CertificateFactory.getInstance("X.509");
					InputStream cipherStream = new ByteArrayInputStream(input.readNBytes(input.readInt()));
					Certificate cipherCert = cf.generateCertificate(cipherStream);
					Server.setClientPublicKey(cipherCert.getPublicKey());
					
					String originalFileName = new String(input.readNBytes(input.readInt()));
					
					System.out.println("Comprobando firma");

					Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(cerFirma));
					ObjectOutputStream responseStream = new ObjectOutputStream(aClient.getOutputStream());
					
					if(Validation.validateCert(certificate, Server.getTrust())) {
						if (Validation.checkSign(certificate, desencriptado,sign)) {
							//PASAMOS AL GUARDADO DEL ARCHIVO
							System.out.println("\nFirma verificada.");
							System.out.println("Procedemos a guardar el archivo");
							FileSave file = new FileSave(cerFirma, desencriptado, sign,clave,isPrivate,savePath,signAlias);
							String fileName = file.getFileName();

							String ruta_save=savePath+fileName+"/"+originalFileName;
							FileOutputStream filedef =new FileOutputStream(ruta_save);
							// Comprobamos confidencialidad 

							if (isPrivate) {
								
								ArrayList<byte[]> tuple = Encription.encriptDocument(desencriptado, secretKeyAlias, contrasenha, algoritmo, Server.getKeyStore());
								
								Server.setLocalCipherParams(tuple.get(0));
								
								privado.add(fileName);
								filedef.write(tuple.get(1));
								filedef.close();

								responseStream.writeObject(file.getResponse());
								System.out.println("Server: Archivo guardado"); 
							}
							else
							{
								publico.add(fileName);
								filedef.write(desencriptado);
								filedef.close();

								responseStream.writeObject(file.getResponse());

								System.out.println("Server: Archivo guardado");
							}
						} else {
							//Firma incorrecta
							System.out.println("\nFirma incorrecta.");
							responseStream.writeObject(new Response(-2));
						}
					}else {
						//Certificado invalido
						responseStream.writeObject(new Response(-1));
					}
					responseStream.close();
					aClient.close();
				} catch (Exception e) {
					e.printStackTrace();
					ObjectOutputStream responseStream = null;
					try {
						responseStream = new ObjectOutputStream(aClient.getOutputStream());
						responseStream.writeObject(new Response(-10));
						responseStream.close();
						aClient.close();
					} catch (IOException e1) {
						e1.printStackTrace();
					}
				}
			}
		}.start();
	}

}
