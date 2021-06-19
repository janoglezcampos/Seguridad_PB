package clientpart;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Files;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import server.Util;

public class Util3 {

	public static void start(final Socket client2, String idRegistro, String cert_rec) {
		// TODO Auto-generated method stub
		
		
		 System.out.println("client start SEND ");
	      new Thread() {
	         public void run() {
	        	 
	        	 
	        	try { 
	        	    
	        		String op = "3"; 
		        	 DataOutputStream out;
				
						out = new DataOutputStream(client2.getOutputStream());
						out.writeInt(op.getBytes().length);
			            out.write(op.getBytes());
			            out.flush();
	        		
	        		
	        		
	        		File data = new File(cert_rec);
		            byte [] certFirma= Files.readAllBytes(data.toPath());
 
		            InputStream in = new ByteArrayInputStream(certFirma);
		    		CertificateFactory cf   = CertificateFactory.getInstance("X.509");
		    		Certificate certificate = cf.generateCertificate(in);
					
	     			X509Certificate extra= (X509Certificate) certificate ;
	     			Principal idPropietario = extra.getIssuerDN();
	     			System.out.println("ID PROPIETARIO: "+ idPropietario.toString());
	     			
	     			
	     			
	     			
	     			out.writeInt(certFirma.length);
	     			out.write(certFirma);
	     			out.flush();
	     			out.writeInt(idRegistro.getBytes().length);
	     			out.write(idRegistro.getBytes());
	     			out.flush();
	     			
	     			DataInputStream input= new DataInputStream(client2.getInputStream());
	     			String direct= "C:\\Users\\usuario\\Desktop\\alamcenes\\apartado3";
	     			FileOutputStream filedef =new FileOutputStream(direct+"/firmaDocumento");
		       		filedef.write(input.readNBytes(input.readInt()));
		       		filedef.close();
		       		FileOutputStream filedef2 =new FileOutputStream(direct+"/idRegistro");
		       		filedef2.write(input.readNBytes(input.readInt()));
		       		filedef2.close();
		       		FileOutputStream filedef3=new FileOutputStream(direct+"/selloTemporal");
		       		filedef3.write(input.readNBytes(input.readInt()));
		       		filedef3.close();
		       		FileOutputStream filedef4=new FileOutputStream(direct+"/firmaSigRD");
		       		filedef4.write(input.readNBytes(input.readInt()));
		       		filedef4.close();
		       		FileOutputStream filedef5=new FileOutputStream(direct+"/confidencialidad");
		       		filedef5.write(input.readNBytes(input.readInt()));
		       		filedef5.close();
		       		FileOutputStream filedef6=new FileOutputStream(direct+"/imagen");
		       		filedef6.write(input.readNBytes(input.readInt()));
		       		filedef6.close();
		       		   	  
	     			
		         
		            
		               
		            BufferedReader input2 = new BufferedReader(new InputStreamReader(client2.getInputStream()));
		            String received = input2.readLine();
		            System.out.println("Received : "+"\n" + received);
		            input.close();
		     		
	        	 
	        	} catch (IOException | CertificateException e) {
	     			// TODO Auto-generated catch block
	     			e.printStackTrace();
	     		}
	     		
	        	 
	        	 
	        	 
	        	 
	        	 
	        	 
	        	 
	        	 
	        	 
	        	 
	       
	        
	            
	            	  
	            	  
	            	   
			
			
	            }
	         
	         
	            }.start();
		
		
		
		
		
		
		
	
	
	
	
	
	}
}
