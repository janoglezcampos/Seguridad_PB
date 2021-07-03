package common;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.ArrayList;

public class Validation {

	public static boolean validateCert(Certificate cert, KeyStore trust) throws Exception {
		try {
			ArrayList<X509Certificate> mylist = new ArrayList<X509Certificate>();
			mylist.add((X509Certificate) cert);
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			CertPath certPath = certificateFactory.generateCertPath(mylist); 
			CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
			PKIXParameters parameters = new PKIXParameters(trust);
			parameters.setRevocationEnabled(false);
			certPathValidator.validate(certPath, parameters); 
			return true;
		} catch (CertPathValidatorException | CertificateException e) {
			return false;
		}
	}

	public static boolean checkSign(Certificate cert, byte[] content, byte[] sign)
			throws NoSuchAlgorithmException, InvalidKeyException {
		try {
			Signature firma = Signature.getInstance("MD5withRSA");
			PublicKey verificacion = cert.getPublicKey();
			firma.initVerify(verificacion);
			firma.update(content);
			firma.verify(sign);
			return true;
		} catch (SignatureException se) {
			System.out.println("Error verificando firma: " + se);
			return false;
		}
	}

	public static byte[] signContent(byte[] content, PrivateKey signkey)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature firma = Signature.getInstance("MD5withRSA");
		firma.initSign(signkey);
		firma.update(content);
		return firma.sign();
	}

	public static byte[] getSignRDContent(int idRegistro, String selloTemporal, String idPropietario,
			byte[] nonEncriptedFile, byte[] firmaDoc) throws Exception {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(idRegistro);
		outputStream.write(selloTemporal.getBytes());
		outputStream.write(idPropietario.toString().getBytes());
		outputStream.write(nonEncriptedFile);
		outputStream.write(firmaDoc);

		return outputStream.toByteArray();
	}

}
