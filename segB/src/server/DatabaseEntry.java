package server;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;

import common.*;

public class DatabaseEntry implements Serializable{
	
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

	public DatabaseEntry(int idRegistro, boolean isPrivate, String originalFileName,Certificate certificate, byte[] file, byte[] firmaDoc, KeyStore keystore, String keySignAlias, char[] clave, PublicKey clientPublicKey) throws Exception{
		this.firmaDoc = firmaDoc;
		this.idRegistro = idRegistro;
		this.isPrivate = isPrivate;
		this.originalFileName = originalFileName;
		this.clientPublicKey = clientPublicKey;
		
		idPropietario = ((X509Certificate)certificate).getIssuerDN().toString();

		this.sello= sello();

		byte conjunto[] = Validation.getSignRDContent(idRegistro, sello(), idPropietario.toString(), file, firmaDoc);

		sigRD = Validation.signContent(conjunto, (PrivateKey) keystore.getKey(keySignAlias, clave));
	}

	public void addFileContent(byte[] content, byte[] cipherParams) {
		this.content = content;
		this.cipherParams = cipherParams;
	}

	public void addFileContent(byte[] content) {
		this.content = content;
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
		String dataBaseFileName = idRegistro+"_"+idPropietario+".sig";
		return dataBaseFileName = (!isPrivate) ? dataBaseFileName : dataBaseFileName+".cif";
	}
	
	/*
	public Response save(String path) throws Exception {
		String dataBaseFileName = idRegistro+"_"+idPropietario+".sig";

		dataBaseFileName = (!isPrivate) ? dataBaseFileName : dataBaseFileName+".cif";
		FileOutputStream fos = new FileOutputStream(Paths.get(path, dataBaseFileName).toString());
		DataOutputStream dos = new DataOutputStream(fos);
		dos.writeInt(idRegistro);
		dos.writeInt((isPrivate) ? 1:0);
		dos.writeInt(firmaDoc.length);
		dos.write(firmaDoc);
		dos.writeInt(sello.getBytes().length);
		dos.write(sello.getBytes());
		dos.writeInt(bytesfirma.length);
		dos.write(bytesfirma.length);
		dos.writeInt(originalFileName.getBytes().length);
		dos.write(originalFileName.getBytes());
		dos.writeInt(clientPublicKey.getEncoded().length);
		dos.write(clientPublicKey.getEncoded());
		dos.writeInt(content.length);
		dos.write(content);
		if(isPrivate) {
			dos.writeInt(cipherParams.length);
			dos.write(cipherParams);
		}
		fos.close();
		dos.close();
		return new Response(idRegistro, sello, idPropietario.toString(), bytesfirma, Server.getKeyStore().getCertificate(signAlias));
	}
	*/

	private static String sello() {
		Calendar fecha = new GregorianCalendar();

		int anho = fecha.get(Calendar.YEAR);
		int mes = fecha.get(Calendar.MONTH);
		int dia = fecha.get(Calendar.DAY_OF_MONTH);
		int hora = fecha.get(Calendar.HOUR_OF_DAY);
		int minuto = fecha.get(Calendar.MINUTE);
		int segundo = fecha.get(Calendar.SECOND);

		String def= anho+"/"+mes+"/"+dia+" "+hora+":"+minuto+":"+segundo;
		System.out.println(def);
		return def;
	}

	public static ArrayList<ArrayList<String>> getFiles(String savePath,String propietario){
		File[] fileList =new File (savePath).listFiles();
		ArrayList<ArrayList<String>> complete = new ArrayList<ArrayList<String>>();
		ArrayList<String> privateFiles = new ArrayList<String>();
		ArrayList<String> publicFiles = new ArrayList<String>();
		String name;
		for(File file: fileList){
			name = file.getName();
			if(name.endsWith(".cif")) {
				privateFiles.add(name);
			}
			else if(name.endsWith(".sig")) {
				publicFiles.add(name);
			}
		}
		complete.add(publicFiles);
		complete.add(privateFiles);
		return complete;
	}
}
