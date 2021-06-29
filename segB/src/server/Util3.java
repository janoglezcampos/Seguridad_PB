package server;

import common.*;

import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import java.security.cert.*;
import java.util.ArrayList;


public class Util3 {
	private static String savePath="/Users/lexy/Desktop/Clases/Seguridad/serverSavedFiles/";
	private static String secretKeyAlias = "dataenckey";
	private static String signAlias = "serversign";

	public static void start(Socket aClient, String algorithm, String passwd_key) {
		new Thread() {
			public void run() {
				try {
					DataInputStream input= new DataInputStream(aClient.getInputStream());

					byte [] certAuth= input.readNBytes(input.readInt());
					String id_registro=new String(input.readNBytes(input.readInt()));  

					InputStream in = new ByteArrayInputStream(certAuth);
					CertificateFactory cf   = CertificateFactory.getInstance("X.509");
					Certificate certificate = cf.generateCertificate(in);
					Certificate serverCertSign = Server.getKeyStore().getCertificate(signAlias);

					File directorio= new File (savePath);
					String carpeta_comprobar = "";


					ObjectOutputStream response = new ObjectOutputStream(aClient.getOutputStream());
					Response res = null;

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

						ArrayList<byte[]> req = new ArrayList <byte[]>();

						String idPropietario = ((X509Certificate)certificate).getIssuerDN().toString();
						if(esprivado) {
							if(Validation.validateCert(certificate, Server.getTrust())) {
								if ((id_registro+"_"+idPropietario).equals(carpeta_comprobar)) {
									System.out.println("COMPROBACIÓN CORRECTA DE ID: " + carpeta_comprobar);

									req=es_privado(carpeta_comprobar);

									byte [] decriptedFile = Encription.decriptDocument(req.get(5), secretKeyAlias, passwd_key, algorithm, Server.getLocalCipherParams(), Server.getKeyStore());
									req = Encription.encript2sendPGP(req, decriptedFile, Server.getClientPublicKey());
									res = new Response(Integer.parseInt(id_registro), idPropietario, req.get(3).toString(), req.get(6), req.get(7), req.get(8), req.get(4), serverCertSign);
									
								} else {
									res = new Response(-3);
								}
							}else {
								res = new Response(-1);
							}
						}
						else {
							req=es_publico(carpeta_comprobar);
							res = new Response(Integer.parseInt(id_registro), idPropietario, req.get(3).toString(), req.get(5),req.get(4), serverCertSign);
						}
					}else {
						res = new Response(-4);
					}
					response.writeObject(res);
					response.flush();
					response.close();
					in.close();
					aClient.close();
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
}
