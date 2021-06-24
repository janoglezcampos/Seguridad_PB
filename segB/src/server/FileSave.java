package server;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.LinkedList;



public class FileSave {
	
	public static String sigRD (byte [] certFirma, byte[] file, byte[] firmaDoc,char[] clave,String confidencialidad,String savePath, String keySignAlias) throws CertificateException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException{
		
		//SACAMOS IDPROPIETARIO
		InputStream in = new ByteArrayInputStream(certFirma);
		CertificateFactory cf   = CertificateFactory.getInstance("X.509");
		Certificate certificate = cf.generateCertificate(in);
		X509Certificate extra= (X509Certificate) certificate ;
		Principal idPropietario = extra.getIssuerDN();
		System.out.println(extra.getSubjectDN().toString());
		System.out.println("ID PROPIETARIO: "+ idPropietario.toString());
		
		// PASAMOS A GENERERAR LA FIRMA
		int idRegistro= Server.getContador();
		Server.incremetarContador();
	
		String sello= sello();
		//byte  F= (byte) idRegistro; //recordar para pasar e imprimir hacer &0xff
		
	    ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
	    outputStream.write(idRegistro);
	    outputStream.write(sello.getBytes());
	    outputStream.write(idPropietario.toString().getBytes());
	    outputStream.write(file);
	    outputStream.write(firmaDoc);

	    byte conjunto[] = outputStream.toByteArray();
		
		PrivateKey clavekey = (PrivateKey) Server.getKeyStore().getKey(keySignAlias, clave);
		Signature firma =Signature.getInstance("MD5withRSA");
		firma.initSign(clavekey);
		firma.update(conjunto); 
		byte[] bytesfirma= firma.sign();
		
		String nombreFichero= Integer.toString(idRegistro)+"_"+idPropietario.toString();
		 
		guardado (firmaDoc,idRegistro,sello,bytesfirma,nombreFichero, confidencialidad,savePath);
		
		return nombreFichero;
	}


	public static void guardado (byte[] firmaDoc, int idRegistro, String sello, byte[] bytesfirma, String nombreFichero,String confidencialidad,String savePath) throws IOException {
		
		 String ruta_save=savePath+nombreFichero;
		 File directorio = new File(ruta_save);
		 if (!directorio.exists()) {
	            if (directorio.mkdirs()) {
	                System.out.println("Directorio creado");
	            } else {
	                System.out.println("Error al crear directorio");
	            }
	        }
		 
		 
		 String FF= Integer.toString(idRegistro);

		 FileOutputStream filedef =new FileOutputStream(ruta_save+"/firmaDocumento");
		 filedef.write(firmaDoc);
		 filedef.close();
		 FileOutputStream filedef2 =new FileOutputStream(ruta_save+"/idRegistro");
		 filedef2.write(FF.getBytes());
		 filedef2.close();
		 FileOutputStream filedef3=new FileOutputStream(ruta_save+"/selloTemporal");
		 filedef3.write(sello.getBytes());
		 filedef3.close();
		 FileOutputStream filedef4=new FileOutputStream(ruta_save+"/firmaSigRD");
		 filedef4.write(bytesfirma);
		 filedef4.close();
		 FileOutputStream filedef5=new FileOutputStream(ruta_save+"/confidencialidad");
		 filedef5.write(confidencialidad.getBytes());
		 filedef5.close();
	
	}
	

	

	
	public static String sello() {

        Calendar fecha = new GregorianCalendar();
                                                  
        int anho = fecha.get(Calendar.YEAR);
        int mes = fecha.get(Calendar.MONTH);
        int dia = fecha.get(Calendar.DAY_OF_MONTH);
        int hora = fecha.get(Calendar.HOUR_OF_DAY);
        int minuto = fecha.get(Calendar.MINUTE);
        int segundo = fecha.get(Calendar.SECOND);
  
        //System.out.println("Fecha Actual: " + dia + "/" + (mes+1) + "/" + a�o+minuto); 

        //System.out.printf("Hora Actual: %02d:%02d:%02d %n", hora, minuto, segundo);
        
        String def= anho+"/"+mes+"/"+dia+" "+hora+":"+minuto+":"+segundo;
        System.out.println(def);
        return def;
	}
	
	
	

}
