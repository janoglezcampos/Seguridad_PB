package common;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class Validation {

	public static boolean validateCert(Certificate cert, KeyStore trust) throws Exception{
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

	public static boolean checkSign(Certificate cert, byte[] content, byte[] sign) throws NoSuchAlgorithmException, InvalidKeyException {
		try {
			Signature firma =Signature.getInstance("MD5withRSA");
			PublicKey verificacion =cert.getPublicKey();
			firma.initVerify(verificacion);
			firma.update(content);
			firma.verify(sign);
			return true;
		}
		catch (SignatureException se){
			System.out.println("Error verificando firma: " + se);
			return false;
		}
	}
	
	public static byte[] signContent(byte [] content, PrivateKey signkey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature firma =Signature.getInstance("MD5withRSA");
		firma.initSign(signkey);
		firma.update(content);
		return firma.sign();
	}
	
	public static byte[] getSignRDContent(int idRegistro, String selloTemporal,String idPropietario, byte[] nonEncriptedFile, byte[] firmaDoc) throws Exception {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write(idRegistro);
		outputStream.write(selloTemporal.getBytes());
		outputStream.write(idPropietario.toString().getBytes());
		outputStream.write(nonEncriptedFile);
		outputStream.write(firmaDoc);

		return outputStream.toByteArray();
	}
	
	//Dos clientes distintos tienen el mismo issuerDN si su certificado está firmado por la misma CA,
	//para identificar al propietario es necesario usar el SubejctDN también.
	public static String getIdentity(Certificate cert) {
		boolean completeDN = false;
		String issuerDN = ((X509Certificate)cert).getIssuerDN().toString();
		String subjectDN = ((X509Certificate)cert).getSubjectDN().toString();
		return (completeDN) ? (issuerDN+subjectDN) : issuerDN;
	}

}
