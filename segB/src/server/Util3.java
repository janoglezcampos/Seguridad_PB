package server;

import common.*;

import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import java.security.cert.*;
import java.util.ArrayList;

public class Util3 {
	private static final String SAVEPATH = Server.SAVEPATH;
	private static final String SECRETKEYALIAS = Server.SECRETKEYALIAS;
	private static final String SIGNALIAS = Server.SIGNALIAS;

	public static void retrieveFile(Socket aClient, String algorithm, String passwd_key) {
		new Thread() {
			public void run() {
				try {
					DataInputStream input = new DataInputStream(aClient.getInputStream());

					byte[] certAuth = input.readNBytes(input.readInt());
					String id_registro = new String(input.readNBytes(input.readInt()));

					InputStream in = new ByteArrayInputStream(certAuth);
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					Certificate certificate = cf.generateCertificate(in);
					Certificate serverCertSign = Server.getKeyStore().getCertificate(SIGNALIAS);

					ObjectOutputStream response = new ObjectOutputStream(aClient.getOutputStream());
					Response res = null;

					boolean esprivado = false;

					String idPropietario = ((X509Certificate) certificate).getIssuerDN().toString();

					ArrayList<ArrayList<String>> fileList = DatabaseEntry.getFiles(SAVEPATH, idPropietario);
					ArrayList<String> publico = fileList.get(0);
					ArrayList<String> privado = fileList.get(1);

					String fileToRetrieve = null;

					// initContador esta preparado para soportar eliminacion de documentos a mano,
					// pero no esta funcion!!
					if (Integer.parseInt(id_registro) <= Server.getContador()) {
						for (String fileName : privado) {
							if (esprivado = fileName.startsWith(id_registro)) {
								fileToRetrieve = fileName;
							}
						}

						if (esprivado) {
							if (Validation.validateCert(certificate, Server.getTrust())) {
								if ((id_registro + "_" + idPropietario + ".sig.cif").equals(fileToRetrieve)) {
									System.out.println("Propietario correcto, recuperando archivo: " + fileToRetrieve);

									ArrayList<byte[]> encripted2send = new ArrayList<byte[]>();
									FileInputStream fileIn = new FileInputStream(
											Paths.get(SAVEPATH, fileToRetrieve).toString());
									ObjectInputStream objectIn = new ObjectInputStream(fileIn);
									DatabaseEntry dataEntry = (DatabaseEntry) objectIn.readObject();

									byte[] decriptedFile = Encription.decriptDocument(dataEntry.getContent(),
											SECRETKEYALIAS, passwd_key, algorithm, dataEntry.getCipherParams(),
											Server.getKeyStore());

									encripted2send = Encription.encript2sendPGP(decriptedFile,
											dataEntry.getClientPublicKey());
									res = new Response(Integer.parseInt(id_registro), idPropietario,
											dataEntry.getSello(), encripted2send.get(0), encripted2send.get(1),
											encripted2send.get(2), dataEntry.getSigRD(), serverCertSign);
								} else {
									res = new Response(-3);
								}
							} else {

								res = new Response(-1);
							}
						} else {
							for (String fileName : publico) {
								if (fileName.startsWith(id_registro)) {
									fileToRetrieve = fileName;
								}
							}

							FileInputStream fileIn = new FileInputStream(
									Paths.get(SAVEPATH, fileToRetrieve).toString());
							ObjectInputStream objectIn = new ObjectInputStream(fileIn);
							DatabaseEntry dataEntry = (DatabaseEntry) objectIn.readObject();

							res = new Response(Integer.parseInt(id_registro), idPropietario, dataEntry.getSello(),
									dataEntry.getContent(), dataEntry.getSigRD(), serverCertSign);
						}
					} else {
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
}
