package server;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.AlgorithmParameters;
import java.security.KeyStore;
import java.security.KeyStore.SecretKeyEntry;
import java.security.Principal;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;



public class Util {

	//byte [] recv;
	//static byte [] array;
	//static ArrayList <Byte>  datos = new ArrayList <Byte>();
	static ArrayList <String> privado = new ArrayList <String>();
	static ArrayList <String> publico = new ArrayList <String>();

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

	static java.io.ByteArrayOutputStream byteout = new java.io.ByteArrayOutputStream();

	public static void startServerWorking(final Socket aClient, String algoritmo, String contrasenha) {
		//algoritmo es para lo de tipo de confidencialidad
		new Thread() {
			public void run() {
				try {
					ArrayList <byte []> full = new ArrayList <byte[]>();
					DataInputStream input= new DataInputStream(aClient.getInputStream());
					String name_file="";
					System.out.println("Input entrante");
					String confidencialidad =new String (input.readNBytes(input.readInt()));
					System.out.println("Confidencialidad  "+confidencialidad);

					if (confidencialidad.equals("PRIVADO")) {

						System.out.println("Input entrante");
						full.add(input.readNBytes(input.readInt()));
						System.out.println("TAMAÑO FILE ECRIPTADO "+ full.get(0).length);

						System.out.println("Input entrante");
						full.add(input.readNBytes(input.readInt()));
						System.out.println("TAMAÑO PARAMETROS "+ full.get(1).length);

						System.out.println("Input entrante");
						full.add(input.readNBytes(input.readInt()));
						System.out.println("TAMAÑO CLAVE ENCRIPTADA "+ full.get(2).length);

						System.out.println("Input entrante");
						full.add(input.readNBytes(input.readInt()));
						System.out.println("TAMAÑO FIRMA  "+ full.get(3).length);

						System.out.println("Input entrante");
						byte[] cala =input.readNBytes(input.readInt());
						name_file= new String(cala);
						System.out.println("Nombre archivo  "+ name_file);

						System.out.println("Input entrante");
						full.add(input.readNBytes(input.readInt()));
						System.out.println("TAMAÑO CERTFIRMA "+ full.get(4).length);

						System.out.println("Input entrante");
						full.add(input.readNBytes(input.readInt()));
						System.out.println("TAMAÑO CERTCIFRADO "+ full.get(5).length);

					}else {

						System.out.println("Input entrante");
						full.add(input.readNBytes(input.readInt()));
						System.out.println("TAMAÑO FILE "+ full.get(0).length);

						System.out.println("Input entrante");
						full.add(input.readNBytes(input.readInt()));
						System.out.println("TAMAÑO FIRMA  "+ full.get(1).length);

						System.out.println("Input entrante");
						byte[] cala =input.readNBytes(input.readInt());
						name_file= new String(cala);
						System.out.println("Nombre archivo  "+ name_file);

						System.out.println("Input entrante");
						full.add(input.readNBytes(input.readInt()));
						System.out.println("TAMAÑO CERTFIRMA "+ full.get(2).length);

						System.out.println("Input entrante");
						full.add(input.readNBytes(input.readInt()));
						System.out.println("TAMAÑO CERTCIFRADO "+ full.get(3).length);

					}

					char[] clave = contrasenha.toCharArray();
					byte [] desencriptado;
					if (confidencialidad.equals("PRIVADO")) {  

						//Pasamos al desencriptado  
						System.out.println("Desencriptando LA CLAVE ");
						String name ="cifrados";
						Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
						cipher.init(Cipher.DECRYPT_MODE,  Server.getKeyStore().getKey(name,clave));
						byte [] clave_desencriptada=cipher.doFinal(full.get(2));

						System.out.println("Desencriptando El Archivo ");
						SecretKey key = new SecretKeySpec(clave_desencriptada,0,clave_desencriptada.length,"AES");
						System.out.println("Tamaño de clave de desencriptado "+key.getEncoded().length);
						System.out.println("Formato "+ key.getFormat());
						cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); 
						AlgorithmParameters params= AlgorithmParameters.getInstance("AES", "SunJCE");
						params.init(full.get(1));
						cipher.init(Cipher.DECRYPT_MODE, key,params);
						desencriptado=cipher.doFinal(full.get(0));

					} else {
						desencriptado=full.get(0);
					}
					//pasamos a verificar firma 
					System.out.println("Comprobando firma");
					Signature firma =Signature.getInstance("MD5withRSA");
					InputStream in = new ByteArrayInputStream(full.get(2));
					if(confidencialidad.equals("PRIVADO")) {
						in = new ByteArrayInputStream(full.get(4));
					}
					else { in = new ByteArrayInputStream(full.get(2));}

					CertificateFactory cf   = CertificateFactory.getInstance("X.509");
					Certificate certificate = cf.generateCertificate(in);
					X509Certificate extra= (X509Certificate) certificate;
					Principal idPropietario = extra.getIssuerDN();
					System.out.println("ID PROPIETARIO: "+ idPropietario.toString());

					PublicKey verificacion =certificate.getPublicKey();
					firma.initVerify(verificacion);

					firma.update(desencriptado);

					boolean verificado = true;
					try {
						if(confidencialidad.equals("PRIVADO")) {
							verificado = firma.verify(full.get(3));
						}
						else {verificado = firma.verify(full.get(1));}


					} catch (SignatureException se) {
						verificado = false;
					}


					PrintWriter output = new PrintWriter(aClient.getOutputStream());

					if (verificado) {
						//ESTO SI LA FIRMA ES BUENA SUPONGO??
						//PASAMOS AL GUARDADO DEL ARCHIVO
						System.out.println("\nFirma verificada.");
						System.out.println("Procedemos a guardar el archivo");
						String fichero="";
						if (confidencialidad.equals("PRIVADO")) {
							fichero= FileSave.sigRD(full.get(4), desencriptado, full.get(3),clave,confidencialidad);
						}
						else { fichero= FileSave.sigRD(full.get(2), desencriptado, full.get(1),clave,confidencialidad);}

						String ruta_save="C:\\Users\\usuario\\Desktop\\alamcenes/"+fichero+"/"+name_file;
						FileOutputStream filedef =new FileOutputStream(ruta_save);
						// Comprobamos confidencialidad 

						if (confidencialidad.equals("PRIVADO")) {

							privado.add(fichero);

							KeyGenerator kg= KeyGenerator.getInstance("RC2"); 
							kg.init(128);
							//SecretKey key_private= kg.generateKey();
							SecretKey keyPrivate = (SecretKey) Server.getKeyStore().getKey("dataenckey",null);
							KeyStore.SecretKeyEntry secretKeyEntry = (SecretKeyEntry) Server.getKeyStore().getEntry("dataenckey", null);
							keyPrivate = secretKeyEntry.getSecretKey();
							System.out.println("FORMATO clave de encriptado de info en el server : "+keyPrivate.getFormat());

							//Ciframos el fichero
							String concat= keyPrivate.getFormat()+"/CBC/PKCS5Padding";
							Cipher cipher_private = Cipher.getInstance(concat); 
							cipher_private.init(Cipher.ENCRYPT_MODE, keyPrivate);
							byte [] file_encriptado2=cipher_private.doFinal(desencriptado);
							filedef.write(file_encriptado2);
							filedef.close();
							output.println("Server: Archivo guradado "); 


						}
						else {
							publico.add(fichero);
							filedef.write(desencriptado);
							filedef.close();
							output.println("Server: Archivo guradado"); 
						}

					} else {
						System.out.println("\nFirma incorrecta.");
						output.println("\nFirma incorrecta no se ha guardado el archivo");

					}

					output.flush();
					aClient.close();
				} catch (Exception e) {
					e.printStackTrace();
				}

			}
		}.start();
	}


}
