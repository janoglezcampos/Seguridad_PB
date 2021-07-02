package server;

import common.*;

import java.io.*;
import java.net.Socket;
import java.nio.file.Paths;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.ArrayList;

public class Util {
	// byte [] recv;
	// static byte [] array;
	// static ArrayList <Byte> datos = new ArrayList <Byte>();

	private static final String CIPHERALIAS = Server.CIPHERALIAS;
	private static final String SIGNALIAS = Server.SIGNALIAS;
	private static final String SECRETKEYALIAS = Server.SECRETKEYALIAS;
	private static final String SAVEPATH = Server.SAVEPATH;

	public static void receiveFile(final Socket aClient, String algoritmo, String contrasenha) {
		new Thread() {
			public void run() {
				try {
					ArrayList<byte[]> full = new ArrayList<byte[]>();
					full.clear();
					char[] clave = contrasenha.toCharArray();
					DataInputStream input = new DataInputStream(aClient.getInputStream());
					System.out.println("Input entrante");
					String confidencialidad = new String(input.readNBytes(input.readInt()));
					Boolean isPrivate = confidencialidad.equals("PRIVADO");
					System.out.println("Confidencialidad  " + confidencialidad);
					int listSize = input.readInt();

					for (int i = 0; i < listSize - 2; i++) {
						full.add(input.readNBytes(input.readInt()));
					}
					
					byte[] desencriptado;
					if (isPrivate) {
						desencriptado = Encription.decriptFilePGP(full.get(2), full.get(0), full.get(1), contrasenha,
								CIPHERALIAS, Server.getKeyStore());

					} else {
						desencriptado = full.get(0);
					}

					byte[] sign = (isPrivate) ? full.get(3) : full.get(1);
					byte[] cerFirma = (isPrivate) ? full.get(4) : full.get(2);

					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					InputStream cipherStream = new ByteArrayInputStream(input.readNBytes(input.readInt()));
					Certificate cipherCert = cf.generateCertificate(cipherStream);

					String originalFileName = new String(input.readNBytes(input.readInt()));

					System.out.println("Comprobando firma");

					Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(cerFirma));
					ObjectOutputStream responseStream = new ObjectOutputStream(aClient.getOutputStream());

					if (Validation.validateCert(certificate, Server.getTrust())) {
						if (Validation.checkSign(certificate, desencriptado, sign)) {
							// PASAMOS AL GUARDADO DEL ARCHIVO
							System.out.println("\nFirma verificada.");
							System.out.println("Procedemos a guardar el archivo");
							DatabaseEntry dataEntry = new DatabaseEntry(Server.getContador(), isPrivate,
									originalFileName, certificate, desencriptado, sign, Server.getKeyStore(), SIGNALIAS,
									clave, cipherCert.getPublicKey());

							FileOutputStream fileOut = new FileOutputStream(
									Paths.get(SAVEPATH, dataEntry.getFileName()).toString());
							ObjectOutputStream objectOut = new ObjectOutputStream(fileOut);

							if (isPrivate) {

								ArrayList<byte[]> tuple = Encription.encriptDocument(desencriptado, SECRETKEYALIAS,
										contrasenha, algoritmo, Server.getKeyStore());
								dataEntry.addFileContent(tuple.get(1), tuple.get(0));
								objectOut.writeObject(dataEntry);
								responseStream.writeObject(dataEntry.getResponse(Server.getKeyStore(), SIGNALIAS));

								// responseStream.writeObject(file.getResponse());
								System.out.println("Server: Archivo guardado: " + dataEntry.getIdRegistro());
							} else {
								dataEntry.addFileContent(desencriptado);
								objectOut.writeObject(dataEntry);
								responseStream.writeObject(dataEntry.getResponse(Server.getKeyStore(), SIGNALIAS));

								System.out.println("Server: Archivo guardado");
							}
							Server.incremetarContador();
						} else {
							// Firma incorrecta
							System.out.println("\nFirma incorrecta.");
							responseStream.writeObject(new Response(-2));
						}
					} else {
						// Certificado invalido
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
