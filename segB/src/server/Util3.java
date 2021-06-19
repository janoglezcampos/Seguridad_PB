package server;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Files;
import java.security.Key;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public class Util3 {
	
	
	public static void start(Socket aClient, String passwd_key) {
		
		 new Thread() {
			   
			 public void run() {
		            try {
		           
		            	DataInputStream input= new DataInputStream(aClient.getInputStream());
		
		            	System.out.println("Input entrante: certificado");
			            byte [] cert_rec= input.readNBytes(input.readInt());
			               
			            System.out.println("Input entrante: id de registro");
			            String id_registro=new String(input.readNBytes(input.readInt()));  
			                
				        InputStream in = new ByteArrayInputStream(cert_rec);
				        CertificateFactory cf   = CertificateFactory.getInstance("X.509");
				        Certificate certificate = cf.generateCertificate(in);
							
			     		X509Certificate extra= (X509Certificate) certificate ;
			     		Principal idPropietario = extra.getIssuerDN();

			            String id_Usuario=idPropietario.toString();
			               
			            PrintWriter output = new PrintWriter(aClient.getOutputStream());
			               
			            String directorio= "C:\\Users\\usuario\\Desktop\\alamcenes/";
			            String id_carpeta=id_registro+"_"+id_Usuario;     
			            File directorio2= new File (directorio);
			            String carpeta_comprobar="";
			            boolean esprivado=false;
			            
			            if(Integer.parseInt(id_registro)<=Server.getContador()) { 
			            	File [] contenido =directorio2.listFiles();
				       		ArrayList <String>  contenido2 = new ArrayList <String>();	
				       		
				       		for(int i=0; i<contenido.length; i++) {
				       			contenido2.add(contenido[i].getName());
				       		    if(contenido[i].getName().charAt(0)==(id_registro.charAt(0))) {
				       		    	carpeta_comprobar=contenido[i].getName();
				       		   	}
				       		}
				               
				       		for(int i=0; i<Util.getPrivado().size(); i++) {
				       			if(Util.getPrivado().get(i).charAt(0)==id_registro.charAt(0)) {
				       				esprivado=true;
				       		   	}
				       		}
				       		   	 
				       		DataOutputStream out = new DataOutputStream(aClient.getOutputStream());
				       		ArrayList<byte[]> req = new ArrayList <byte[]>();
				       		
				       		if(esprivado) {
				       		   	    	
				       			if ((id_registro+"_"+id_Usuario).equals(carpeta_comprobar)) {
				       		   	    		
				       				System.out.println("COMPROBACI�N CORRECTA DE ID");
				       		   	    es_privado(carpeta_comprobar);
				       		   	    out.writeInt(req.get(1).length);
				       		   	    out.write(req.get(1));
				       		   	    out.writeInt(req.get(2).length);
				       		   	    out.write(req.get(2));
				       		   	    out.writeInt(req.get(3).length);
				       		   	    out.write(req.get(3));
				       		   	    out.writeInt(req.get(4).length);
				       		   	    out.write(req.get(4));
				       		   	    out.writeInt(req.get(0).length);
				       		   	    out.write(req.get(0));
				       		   	    out.writeInt(req.get(5).length);
				       		   	    out.write(req.get(5));
				       		   	    out.flush();
				       		   	    		
				       		   	} else { 
				       		   		output.println("ACCESO NO PERMITIDO\n");
				            	    output.close();
				       		   	}
				       		  
				       		   	    	
				       		}
				       		else { //si es publico el cet no sirve de nada ???
				       		   	    	
				       		
				       		   	req=es_publico(carpeta_comprobar);
				       		   	  
				       		   	
				       		   	
				       		 //  String direct= "C:\\Users\\usuario\\Desktop\\alamcenes\\prueba";
				       		  // File direct2= new File (direct);
	 
				       		
				       		out.writeInt(req.get(1).length);
				            out.write(req.get(1));
				            out.writeInt(req.get(2).length);
				            out.write(req.get(2));
				            out.writeInt(req.get(3).length);
				            out.write(req.get(3));
				            out.writeInt(req.get(4).length);
				            out.write(req.get(4));
				            out.writeInt(req.get(0).length);
				            out.write(req.get(0));
				            out.writeInt(req.get(5).length);
				            out.write(req.get(5));
				            out.flush();
    	
				       		}

			            }
			            else {
			            	output.println("DOCUMENTO NO EXISTENTE\n");
			            	output.close();
			            }

			               output.println("ok\n");
			               output.close();
		            	
		            } catch (Exception e) {
			               e.printStackTrace();
			            }

	
		         }
		   }.start();

	}
	
	
	public static ArrayList<byte[]> es_publico(String carpeta_comprobar) throws IOException{
		ArrayList<byte[]> req = new ArrayList <byte[]>();
		String ruta= "C:\\Users\\usuario\\Desktop\\alamcenes/"+carpeta_comprobar;
		File directorio2= new File (ruta);
		String [] names2= {"confidencialidad","firmaDocumento","idRegistro","selloTemporal","firmaSigRD"};
		File [] contenido =directorio2.listFiles();
		
		for(int i=0; i<names2.length; i++) {
			for(int j=0; j<contenido.length; j++) {
				if(names2[i].equals(contenido[j].getName())){
					byte [] file =Files.readAllBytes(contenido[j].toPath());
					req.add(file);
				}
			}
		}

		ArrayList <String>  names = new ArrayList <String>();	
		for (int k=0; k<names2.length;k++) {
			names.add(names2[k]);
		}
		
		ArrayList <File>  contenido2 = new ArrayList <File>();	
		
		for(int i=0; i<contenido.length; i++) {
			contenido2.add(contenido[i]);
		}
		
		for (int i=0; i< contenido2.size(); i ++) {
			
			if (!names.contains(contenido2.get(i).getName())) {
				byte [] file2 =Files.readAllBytes(contenido2.get(i).toPath());
				req.add(file2);
		}
			
	}

		return req;
	}
	
	
	
	
	
	
	public static ArrayList<byte[]> es_privado(String carpeta_comprobar) throws IOException{
		ArrayList<byte[]> req = new ArrayList <byte[]>();
		String ruta= "C:\\Users\\usuario\\Desktop\\alamcenes/"+carpeta_comprobar;
		File directorio2= new File (ruta);
		String [] names2= {"confidencialidad","firmaDocumento","idRegistro","selloTemporal","firmaSigRD"};
		File [] contenido =directorio2.listFiles();
		
		for(int i=0; i<names2.length; i++) {
			for(int j=0; j<contenido.length; j++) {
				if(names2[i].equals(contenido[j].getName())){
					byte [] file =Files.readAllBytes(contenido[j].toPath());
					req.add(file);
				}
			}
		}

		ArrayList <String>  names = new ArrayList <String>();	
		for (int k=0; k<names2.length;k++) {
			names.add(names2[k]);
		} 
		
		ArrayList <File>  contenido2 = new ArrayList <File>();	
		
		for(int i=0; i<contenido.length; i++) {
			contenido2.add(contenido[i]);
		}
		
		for (int i=0; i< contenido2.size(); i ++) {
			
			if (!names.contains(contenido2.get(i).getName())) {
				byte [] file2 =Files.readAllBytes(contenido2.get(i).toPath());
				req.add(file2);
		}
			
	}
		return req;
	}
	
	
	
}
