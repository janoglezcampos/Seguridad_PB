package server;

import common.*;

import java.io.*;
import java.net.Socket;
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
					String idRegistro = new String(input.readNBytes(input.readInt()));

					InputStream inCert = new ByteArrayInputStream(certAuth);
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					Certificate certificate = cf.generateCertificate(inCert);
					Certificate serverCertSign = Server.getKeyStore().getCertificate(SIGNALIAS);

					ObjectOutputStream response = new ObjectOutputStream(aClient.getOutputStream());
					Response res = null;

					String idPropietario = DatabaseEntry.getIdentity(certificate);

					ArrayList<ArrayList<String>> fileList = DatabaseEntry.getFiles(SAVEPATH, idPropietario);
					ArrayList<String> publico = fileList.get(0);
					ArrayList<String> privado = fileList.get(1);

					String fileToRetrieve = null;
					DatabaseEntry dataEntry;

					switch (DatabaseEntry.getOwnerByID(SAVEPATH, Integer.parseInt(idRegistro))) {
					case "":
						res = new Response(-4);
						break;
					case "PUB":
						for (String fileName : publico) {
							if (fileName.startsWith(idRegistro)) {
								fileToRetrieve = fileName;
							}
						}

						dataEntry = DatabaseEntry.recoverEntry(SAVEPATH, fileToRetrieve);
						System.out.println("Enviando archivo " + dataEntry.getOriginalFileName());

						res = new Response(Integer.parseInt(idRegistro), idPropietario, dataEntry.getOriginalFileName(),
								dataEntry.getSello(), dataEntry.getContent(), dataEntry.getSigRD(), serverCertSign);
						break;
					default:
						for (String fileName : privado) {
							if (fileName.startsWith(idRegistro)) {
								fileToRetrieve = fileName;
							}
						}

						if (Validation.validateCert(certificate, Server.getTrust())) {
							if ((idRegistro + "_" + idPropietario + ".sig.cif").equals(fileToRetrieve)) {
								ArrayList<byte[]> encripted2send = new ArrayList<byte[]>();

								dataEntry = DatabaseEntry.recoverEntry(SAVEPATH, fileToRetrieve);

								byte[] decriptedFile = Encription.decriptDocument(dataEntry.getContent(),
										SECRETKEYALIAS, passwd_key, algorithm, dataEntry.getCipherParams(),
										Server.getKeyStore());

								encripted2send = Encription.encript2sendPGP(decriptedFile,
										dataEntry.getClientPublicKey());

								res = new Response(Integer.parseInt(idRegistro), idPropietario,
										dataEntry.getOriginalFileName(), dataEntry.getSello(), encripted2send.get(0),
										encripted2send.get(1), encripted2send.get(2), dataEntry.getSigRD(),
										serverCertSign);
							} else {
								res = new Response(-3);
							}
						} else {
							res = new Response(-1);
						}
						break;
					}

					// initContador esta preparado para soportar eliminacion de documentos a mano,
					// pero no esta funcion!!
					response.writeObject(res);
					response.flush();
					response.close();
					inCert.close();
					aClient.close();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}.start();
	}
}
