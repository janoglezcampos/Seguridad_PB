package common;

import java.io.Serializable;
import java.security.cert.Certificate;

public class Response implements Serializable {
	private static final long serialVersionUID = 32L;
	private int nError;
	private int idRegistro;
	private String selloTemporal;
	private String idPropietario;
	private byte[] SigRD;
	private Certificate CertFirmaS;
	
	private boolean isPrivate;
	private byte [] encriptedKey;
	private byte [] encriptedFile;
	private byte [] nonEncriptedFile;
	private byte [] cipherParams;

	public Response(int idRegistro, String selloTemporal, String idPropietario, byte[] SigRD, Certificate CertFirmaS) {
		this.idRegistro = idRegistro;
		this.nError=0;
		this.selloTemporal = selloTemporal;
		this.idPropietario = idPropietario;
		this.SigRD = SigRD;
		this.CertFirmaS = CertFirmaS;
	}

	public Response(int idRegistro, String idPropietario, String selloTemporal, byte[] encriptedFile, byte[] cipherParams, byte[] encriptedKey, byte[] SigRD, Certificate CertFirmaS) {
		this(idRegistro, selloTemporal, idPropietario, SigRD, CertFirmaS);
		this.isPrivate = true;
		this.encriptedFile = encriptedFile;
		this.encriptedKey = encriptedKey;
		this.cipherParams = cipherParams;
	}
	public Response(int idRegistro, String idPropietario, String selloTemporal, byte[] file, byte[] SigRD, Certificate CertFirmaS) {
		this(idRegistro, selloTemporal, idPropietario, SigRD, CertFirmaS);
		this.isPrivate = false;
		this.nonEncriptedFile = file;
	}

	public Response(int nError) {
		this.nError=nError;
	}

	public int getError() {
		return nError;
	}
	public int getIdRegistro() {
		return idRegistro;
	}
	public String getSelloTemporal() {
		return selloTemporal;
	}
	public String getIdPropietario() {
		return idPropietario;
	}
	public byte[] getSigRD() {
		return SigRD;
	}
	public Certificate getCert() {
		return CertFirmaS;
	}
	
	public byte[] getEncriptedKey() {
		return encriptedKey;
	}
	public byte[] getEncriptedFile() {
		return encriptedFile;
	}
	public byte[] getNonEncriptedFile() {
		return nonEncriptedFile;
	}
	public boolean getIsPrivate() {
		return isPrivate;
	}
	public byte[] getCipherParams() {
		return cipherParams;
	}

	public String getErrorMsg() {
		if (nError == 0) return "Respuesta correcta";
		switch(nError) {
		case -1:
			return "Certificado no valido";
		case -2:
			return "Firma incorrecta";
		case -3:
			return "Acceso denegado";
		case -4:
			return "Documento no existente";
		case -5:
			return "Acceso denegado";
		default:
			return "Error no especificado";
		}
	}
}
