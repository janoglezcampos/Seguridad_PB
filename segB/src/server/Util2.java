package server;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import common.Response;
import common.Validation;

public class Util2 {
	private static String savePath = Server.SAVEPATH;

	public static void start(Socket aClient) {
		new Thread() {
			public void run() {
				try {
					DataInputStream input = new DataInputStream(aClient.getInputStream());
					byte[] certAuth = input.readNBytes(input.readInt());

					InputStream inCert = new ByteArrayInputStream(certAuth);
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					Certificate certificate = cf.generateCertificate(inCert);

					String idPropietario = DatabaseEntry.getIdentity(certificate);
					
					DataOutputStream out = new DataOutputStream(aClient.getOutputStream());
					ObjectOutputStream out_obj = new ObjectOutputStream(out);

					if (Validation.validateCert(certificate, Server.getTrust())) {


						String confidencialidad = new String(input.readNBytes(input.readInt()));
						ArrayList<ArrayList<String>> complete;

						ArrayList<String> listToSend = new ArrayList<String>();
						complete=DatabaseEntry.getFiles(savePath, idPropietario);

						if (confidencialidad.equals("PRIV")) {
							for (String file : complete.get(1))
								listToSend.add(DatabaseEntry.recoverEntry(savePath, file).getInfo());
						} else if (confidencialidad.equals("PUB")) {
							for (String file : complete.get(0))
								listToSend.add(DatabaseEntry.recoverEntry(savePath, file).getInfo());
						}

						out_obj.writeObject(new Response(listToSend));
						out_obj.flush();
						out_obj.close();
					}else {
						out_obj.writeObject(new Response(-1));
						out_obj.flush();
						out_obj.close();
					}
					out.close();
					input.close();
					out_obj.close();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}.start();
	}

}