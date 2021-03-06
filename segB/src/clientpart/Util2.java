package clientpart;

import java.io.*;
import java.net.Socket;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import common.Response;

public class Util2 {
	private static final String AUTH_ALIAS = Client.AUTH_ALIAS;

	public static void start(final Socket client2, String confidencialidad2) {
		try {
			String op = "2";
			DataOutputStream out;

			out = new DataOutputStream(client2.getOutputStream());
			out.writeInt(op.getBytes().length);
			out.write(op.getBytes());
			out.flush();

			Certificate certificate = Client.getKeyStore().getCertificate(AUTH_ALIAS);
			byte[] certBytes;
			try {
				certBytes = certificate.getEncoded();
				out.writeInt(certBytes.length);
				out.write(certBytes);
				out.flush();
			} catch (CertificateEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return;
			}

			out.writeInt(confidencialidad2.getBytes().length);
			out.write(confidencialidad2.getBytes());
			out.flush();

			DataInputStream input = new DataInputStream(client2.getInputStream());
			ObjectInputStream input_obj = new ObjectInputStream(input);

			Response resp = (Response) input_obj.readObject();

			String format = "%-20s%-40s%-30s%-30s%n";
			String fieldName[] = { "ID de registro: ", "ID de propietario: ", "Nombre del documento: ", "Fecha:" };
			System.out.printf(format, fieldName);
			if (resp.getError() == 0) {
				for (String info : resp.getFileList())
					System.out.printf(format, info.split("\\|"));
			} else {
				System.out.println(resp.getErrorMsg());
			}

			input.close();
			input_obj.close();
			out.close();
			client2.close();

		} catch (IOException | KeyStoreException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

	}

}
