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

	public static void startServerWorking(final Socket aClient, String algoritmo, String contrasenha) {
		//algoritmo es para lo de tipo de confidencialidad
		new Thread() {
			public void run() {
				try {
					ArrayList <byte []> full = new ArrayList <byte[]>();
					full.clear();
					DataInputStream input= new DataInputStream(aClient.getInputStream());
					String name_file="";
					System.out.println("Input entrante");
					String confidencialidad =new String (input.readNBytes(input.readInt()));
					Boolean isPrivate = confidencialidad.equals("PRIVADO");
					System.out.println("Confidencialidad  "+confidencialidad);
					/*
					 PRIVADO:
						 Cofidencialidad
						 Archivo 0
						 Parametros 1
						 Clave 2
						 Firma 3
						 Nombre de archivo 
						 Certificado firma 4
						 Cerificado cifrado
					 PUBLICO:
						 Confidencialidad
						 Archivo 0
						 Firma 1
						 Nombre de documento
						 Certificado de firma 2
						 Cerificado de cifrado
					 */
					if (isPrivate) {

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

						CertificateFactory cf   = CertificateFactory.getInstance("X.509");
						InputStream cipherStream = new ByteArrayInputStream(input.readNBytes(input.readInt()));
						Certificate cipherCert = cf.generateCertificate(cipherStream);
						Server.setClientPublicKey(cipherCert.getPublicKey());

					}
					else 
					{
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

						CertificateFactory cf   = CertificateFactory.getInstance("X.509");
						InputStream cipherStream = new ByteArrayInputStream(input.readNBytes(input.readInt()));
						Certificate cipherCert = cf.generateCertificate(cipherStream);
						Server.setClientPublicKey(cipherCert.getPublicKey());
					}
					byte[] sign = (isPrivate) ? full.get(3) : full.get(1);
					byte[] cerFirma = (isPrivate) ? full.get(4) : full.get(2);

					//
					byte [] desencriptado;
					if (isPrivate) {
						/*
						//Pasamos al desencriptado
						System.out.println("Desencriptando LA CLAVE ");
						Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
						cipher.init(Cipher.DECRYPT_MODE,  Server.getKeyStore().getKey(cipherAlias,clave));
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
						 */
						desencriptado = Encription.decriptFilePGP(full.get(2), full.get(0), full.get(1), contrasenha, cipherAlias, Server.getKeyStore());

					} else {
						desencriptado=full.get(0);
					}
					//pasamos a verificar firma 
					System.out.println("Comprobando firma");

					CertificateFactory cf   = CertificateFactory.getInstance("X.509");
					Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(cerFirma));
					
					ObjectOutputStream responseStream = new ObjectOutputStream(aClient.getOutputStream());
					
					if(validateCert(certificate, Server.getTrust())) {

						char[] clave = contrasenha.toCharArray();
						if (checkSign(certificate, desencriptado,sign)) {
							//PASAMOS AL GUARDADO DEL ARCHIVO
							System.out.println("\nFirma verificada.");
							System.out.println("Procedemos a guardar el archivo");
							FileSave file;
							if (isPrivate) 
							{
								file = new FileSave(full.get(4), desencriptado, full.get(3),clave,isPrivate,savePath,signAlias);
								//fichero= FileSave.sigRD(full.get(4), desencriptado, full.get(3),clave,confidencialidad,savePath,signAlias);
							}
							else { 
								file = new FileSave(full.get(2), desencriptado, full.get(1),clave,isPrivate,savePath,signAlias);
								//fichero= FileSave.sigRD(full.get(2), desencriptado, full.get(1),clave,confidencialidad,savePath,signAlias);
							}

							String fileName = file.getFileName();

							String ruta_save=savePath+fileName+"/"+name_file;
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
							responseStream.writeObject(new Response(-2,1));
						}
					}else {
						//Certificado invalido
						responseStream.writeObject(new Response(-1,1));
					}
					responseStream.close();
					aClient.close();
				} catch (Exception e) {
					e.printStackTrace();
					ObjectOutputStream responseStream = null;
					try {
						responseStream = new ObjectOutputStream(aClient.getOutputStream());
						responseStream.writeObject(new Response(-3,1));
						responseStream.close();
						aClient.close();
					} catch (IOException e1) {
						e1.printStackTrace();
					}
				}
			}
		}.start();
	}

	static private boolean validateCert(Certificate cert, KeyStore trust) throws Exception{
		try {
			List<X509Certificate> mylist = new ArrayList<X509Certificate>();          
			mylist.add((X509Certificate) cert);
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			//InputStream is = new ByteArrayInputStream(in);
			CertPath certPath = certificateFactory.generateCertPath(mylist); // Throws Certificate Exception when a cert path cannot be generated
			CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
			PKIXParameters parameters = new PKIXParameters(trust);
			parameters.setRevocationEnabled(false);
			certPathValidator.validate(certPath, parameters); // This will throw a CertPathValidatorException if validation fails
			return true;
		}
		catch (CertPathValidatorException | CertificateException e){
			return false;
		}
	}

	static private boolean checkSign(Certificate cert, byte[] decrycpted, byte[] sign) throws Exception{
		try {
			Signature firma =Signature.getInstance("MD5withRSA");
			PublicKey verificacion =cert.getPublicKey();
			firma.initVerify(verificacion);
			firma.update(decrycpted);
			firma.verify(sign);
			return true;
		}
		catch (SignatureException se){
			System.out.println("Error verificando firma: " + se);
			return false;
		}
	}

}
