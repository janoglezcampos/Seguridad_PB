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
	private int forFunctionality;
	
	public Response(int idRegistro, String selloTemporal, String idPropietario, byte[] SigRD, Certificate CertFirmaS) {
		this.forFunctionality = 1;
		this.idRegistro = idRegistro;
		this.nError=0;
		this.selloTemporal = selloTemporal;
		this.idPropietario = idPropietario;
		this.SigRD = SigRD;
		this.CertFirmaS = CertFirmaS;
	}
	
	public Response(int nError, int forFunctionality) {
		this.nError=nError;
		this.forFunctionality = forFunctionality;
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
	public int getForFunctionality() {
		return forFunctionality;
	}
	
	public String getErrorMsg() {
		if (nError == 0) return "Respuesta correcta";
		
		switch(forFunctionality) {
		case 1:
			switch(nError) {
			case -1:
				return "Certificado no valido";
			case -2:
				return "Firma incorrecta";
			default:
				return "Error no especificado";
			}
		case 3:
			switch(nError) {
			case -1:
				return "";
			case -2:
				return "";
			default:
				return "Error desconocido";
			}
		default:
			return "Funcionalidad no establecida en la respuesta";
		}
	}
}
