package server;

import java.io.*;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

import common.*;

public class DatabaseEntry implements Serializable {

	private static final long serialVersionUID = 12L;
	private final String signAlias = "serversign";
	private byte[] sigRD;
	private byte[] firmaDoc;
	private int idRegistro;
	private String sello;
	private byte[] cipherParams;
	private byte[] content;
	private String idPropietario;
	private boolean isPrivate;
	private String originalFileName;
	private PublicKey clientPublicKey;

	public DatabaseEntry(int idRegistro, boolean isPrivate, String originalFileName, Certificate certificate,
			byte[] file, byte[] firmaDoc, KeyStore keystore, String keySignAlias, char[] clave,
			PublicKey clientPublicKey) throws Exception {
		this.firmaDoc = firmaDoc;
		this.idRegistro = idRegistro;
		this.isPrivate = isPrivate;
		this.originalFileName = originalFileName;
		this.clientPublicKey = clientPublicKey;

		idPropietario = getIdentity(certificate);

		this.sello = sello();

		byte conjunto[] = Validation.getSignRDContent(idRegistro, sello(), idPropietario.toString(), file, firmaDoc);

		sigRD = Validation.signContent(conjunto, (PrivateKey) keystore.getKey(keySignAlias, clave));
	}

	public String getSignAlias() {
		return signAlias;
	}

	public byte[] getSigRD() {
		return sigRD;
	}

	public byte[] getFirmaDoc() {
		return firmaDoc;
	}

	public int getIdRegistro() {
		return idRegistro;
	}

	public String getSello() {
		return sello;
	}

	public byte[] getCipherParams() {
		return cipherParams;
	}

	public byte[] getContent() {
		return content;
	}

	public String getIdPropietario() {
		return idPropietario;
	}

	public boolean isPrivate() {
		return isPrivate;
	}

	public String getOriginalFileName() {
		return originalFileName;
	}

	public PublicKey getClientPublicKey() {
		return clientPublicKey;
	}

	public String getInfo() {
		return idRegistro + "|" + idPropietario + "|" + originalFileName + "|" + sello;
	}

	public Response getResponse(KeyStore keystore, String signAlias) {
		try {
			return new Response(idRegistro, sello, idPropietario.toString(), sigRD, keystore.getCertificate(signAlias));
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return new Response(-10);
		}
	}

	public String getFileName() {
		String dataBaseFileName = idRegistro + "_" + idPropietario + ".sig";
		return dataBaseFileName = (!isPrivate) ? dataBaseFileName : dataBaseFileName + ".cif";
	}

	public void addFileContent(byte[] content, byte[] cipherParams) {
		this.content = content;
		this.cipherParams = cipherParams;
	}

	public void addFileContent(byte[] content) {
		this.content = content;
	}

	public static DatabaseEntry recoverEntry(String savePath, String fileName)
			throws ClassNotFoundException, IOException {
		FileInputStream fileIn = new FileInputStream(Paths.get(savePath, fileName).toString());
		ObjectInputStream objectIn = new ObjectInputStream(fileIn);
		return (DatabaseEntry) objectIn.readObject();
	}

	private String sello() {
		Calendar fecha = new GregorianCalendar();

		int anho = fecha.get(Calendar.YEAR);
		int mes = fecha.get(Calendar.MONTH);
		int dia = fecha.get(Calendar.DAY_OF_MONTH);
		int hora = fecha.get(Calendar.HOUR_OF_DAY);
		int minuto = fecha.get(Calendar.MINUTE);
		int segundo = fecha.get(Calendar.SECOND);

		String def = anho + "/" + mes + "/" + dia + " " + hora + ":" + minuto + ":" + segundo;
		System.out.println(def);
		return def;
	}

	public static ArrayList<ArrayList<String>> getFiles(String savePath, String propietario) {
		File[] fileList = new File(savePath).listFiles();

		ArrayList<ArrayList<String>> complete = new ArrayList<ArrayList<String>>();
		ArrayList<String> privateFiles = new ArrayList<String>();
		ArrayList<String> publicFiles = new ArrayList<String>();
		String name;
		for (File file : fileList) {
			name = file.getName();
			if (name.endsWith(".cif") && name.contains(propietario + ".sig")) {
				privateFiles.add(name);
			} else if (name.endsWith(".sig")) {
				publicFiles.add(name);
			}
		}
		complete.add(publicFiles);
		complete.add(privateFiles);
		return complete;
	}

	/**
	 * Returns the owner of the file taking
	 * 
	 * @param savePath
	 * @param idRegistro
	 * @return owner if private, PUB if public or null if the file doesn't exists
	 */
	public static String getOwnerByID(String savePath, int idRegistro) {
		File[] fileList = new File(savePath).listFiles();
		String sId = Integer.toString(idRegistro);
		String fileName;
		for (File file : fileList) {
			fileName = file.getName();
			if (fileName.startsWith(sId)) {
				if (fileName.contains(".cif")) {
					return fileName.substring(fileName.indexOf("_"), fileName.indexOf(".sig"));
				} else {
					return "PUB";
				}
			}
		}
		return "";
	}

	// Dos clientes distintos tienen el mismo issuerDN si su certificado está
	// firmado por la misma CA,
	// para identificar al propietario es necesario usar el SubejctDN también.
	public static String getIdentity(Certificate cert) {
		String issuerDN = ((X509Certificate) cert).getIssuerDN().toString();
		String subjectCN = ((X509Certificate) cert).getSubjectDN().getName();
		return (Server.ID_FROM_SUBJECT) ? (issuerDN + subjectCN) : issuerDN;
	}

}
