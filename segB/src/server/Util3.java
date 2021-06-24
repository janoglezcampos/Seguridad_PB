package server;

import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;
import java.security.cert.*;
import java.util.ArrayList;
import javax.crypto.*;


public class Util3 {
	private static String savePath="/Users/lexy/Desktop/Clases/Seguridad/serverSavedFiles/";
	private static String secretKeyAlias = "dataenckey";

	public static void start(Socket aClient, String algorithm, String passwd_key) {
		new Thread() {
			public void run() {
				try {
					DataInputStream input= new DataInputStream(aClient.getInputStream());

					byte [] cert_rec= input.readNBytes(input.readInt());
					String id_registro=new String(input.readNBytes(input.readInt()));  

					InputStream in = new ByteArrayInputStream(cert_rec);
					CertificateFactory cf   = CertificateFactory.getInstance("X.509");
					Certificate certificate = cf.generateCertificate(in);
					String idPropietario = ((X509Certificate)certificate).getIssuerDN().toString();

					PrintWriter output = new PrintWriter(aClient.getOutputStream());
   
					File directorio= new File (savePath);
					String carpeta_comprobar = "";
					boolean esprivado=false;

					if(Integer.parseInt(id_registro)<=Server.getContador()) {

						File [] contenido =directorio.listFiles();
						ArrayList <String>  contenido2 = new ArrayList <String>();

						for(int i=0; i<contenido.length; i++) {
							contenido2.add(contenido[i].getName());
							if(contenido[i].getName().charAt(0)==(id_registro.charAt(0))) {
								carpeta_comprobar=contenido[i].getName();
							}
						}

						//Si se guardase en ficheros, comprobar por .cif
						for(int i=0; i<Util.getPrivado().size(); i++) {
							if(Util.getPrivado().get(i).charAt(0)==id_registro.charAt(0)) {
								esprivado=true;
							}
						}

						DataOutputStream out = new DataOutputStream(aClient.getOutputStream());
						ArrayList<byte[]> req = new ArrayList <byte[]>();

						if(esprivado) {
							if ((id_registro+"_"+idPropietario).equals(carpeta_comprobar)) {
								System.out.println("COMPROBACIÓN CORRECTA DE ID: " + carpeta_comprobar);
								req=es_privado(carpeta_comprobar);
								out.writeInt(req.get(1).length);
								out.write(req.get(1));
								out.writeInt(req.get(2).length);
								out.write(req.get(2));
								out.writeInt(req.get(3).length);
								out.write(req.get(3));
								out.writeInt(req.get(4).length);
								out.write(req.get(4));
								out.writeInt(req.get(0).length);
								out.write(req.get(0));
								byte [] decriptedFile = decriptDocument(req.get(5), secretKeyAlias, passwd_key, algorithm);
								out.writeInt(decriptedFile.length);
								out.write(decriptedFile);
								out.flush();

							} else {
								output.println("ACCESO NO PERMITIDO\n");
								output.close();
							}
						}
						else { 
							req=es_publico(carpeta_comprobar);
							out.writeInt(req.get(1).length);
							out.write(req.get(1));
							out.writeInt(req.get(2).length);
							out.write(req.get(2));
							out.writeInt(req.get(3).length);
							out.write(req.get(3));
							out.writeInt(req.get(4).length);
							out.write(req.get(4));
							out.writeInt(req.get(0).length);
							out.write(req.get(0));
							out.writeInt(req.get(5).length);
							out.write(req.get(5));
							out.flush();
						}

					}else {
						output.println("DOCUMENTO NO EXISTENTE\n");
						output.close();
					}
					output.println("ok\n");
					output.close();

				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}.start();

	}


	public static ArrayList<byte[]> es_publico(String carpeta_comprobar) throws IOException{
		ArrayList<byte[]> req = new ArrayList <byte[]>();
		String ruta= savePath+carpeta_comprobar;
		
		File directorio2= new File (ruta);
		String [] names2= {"confidencialidad","firmaDocumento","idRegistro","selloTemporal","firmaSigRD"};
		File [] contenido =directorio2.listFiles();

		for(int i=0; i<names2.length; i++) {
			for(int j=0; j<contenido.length; j++) {
				if(names2[i].equals(contenido[j].getName())){
					byte [] file =Files.readAllBytes(contenido[j].toPath());
					req.add(file);
				}
			}
		}

		ArrayList <String>  names = new ArrayList <String>();	
		for (int k=0; k<names2.length;k++) {
			names.add(names2[k]);
		}

		ArrayList <File>  contenido2 = new ArrayList <File>();	

		for(int i=0; i<contenido.length; i++) {
			contenido2.add(contenido[i]);
		}

		for (int i=0; i< contenido2.size(); i ++) {

			if (!names.contains(contenido2.get(i).getName())) {
				byte [] file2 =Files.readAllBytes(contenido2.get(i).toPath());
				req.add(file2);
			}

		}

		return req;
	}

	public static ArrayList<byte[]> es_privado(String carpeta_comprobar) throws IOException{
		ArrayList<byte[]> req = new ArrayList <byte[]>();
		String ruta= savePath+carpeta_comprobar;
		File directorio2= new File (ruta);
		String [] names2= {"confidencialidad","firmaDocumento","idRegistro","selloTemporal","firmaSigRD"};
		File [] contenido =directorio2.listFiles();

		System.out.println("Archivos: "+ contenido.toString());
		
		for(int i=0; i<names2.length; i++) {
			byte [] file =Files.readAllBytes(Paths.get(ruta,names2[i]));
			req.add(file);
		}
		
		ArrayList <String>  names = new ArrayList <String>();	
		for (int k=0; k<names2.length;k++) {
			names.add(names2[k]);
		} 
		
		ArrayList <File>  contenido2 = new ArrayList <File>();	

		for(int i=0; i<contenido.length; i++) {
			contenido2.add(contenido[i]);
		}
		
		for (int i=0; i< contenido2.size(); i ++) {
			if (!names.contains(contenido2.get(i).getName())) {
				byte [] file2 =Files.readAllBytes(contenido2.get(i).toPath());
				req.add(file2);
			}
		}
		return req;
	}
	
	public static byte[] decriptDocument(byte[] document, String keyAlias, String password, String algorithm) throws Exception {
		PasswordProtection pass = new PasswordProtection(password.toCharArray());
		
		SecretKeyEntry secretKeyEntry = (SecretKeyEntry) Server.getKeyStore().getEntry(keyAlias, pass);
		SecretKey keyPrivate = secretKeyEntry.getSecretKey();
		
		String concat= algorithm+"/CBC/PKCS5Padding";
		Cipher cipher_private = Cipher.getInstance(concat);
		
		AlgorithmParameters params= AlgorithmParameters.getInstance(algorithm, "SunJCE");
		params.init(Server.getLocalCipherParams().getEncoded());
		
		cipher_private.init(Cipher.DECRYPT_MODE, keyPrivate,params);
		return cipher_private.doFinal(document);
	}
}
