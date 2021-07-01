package clientpart;



import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;



import common.Response;

public class Util2 {

	private static String authAlias="clientAuth";
	public static void start(final Socket client2, String confidencialidad2) {
		// TODO Auto-generated method stub

		System.out.println("client start SEND ");
		new Thread() {
			public void run() {
				try { 
					String op = "2"; 
					DataOutputStream out;

					out = new DataOutputStream(client2.getOutputStream());
					out.writeInt(op.getBytes().length);
					out.write(op.getBytes());
					out.flush();
					
					Certificate certificate = Client.getKeyStore().getCertificate(authAlias);
					//byte [] certFirma= certificate.getEncoded();
					X509Certificate extra= (X509Certificate) certificate ;
					Principal idPropietario = extra.getIssuerDN();
					//System.out.println("ID PROPIETARIO: "+ idPropietario.toString());

					out.writeInt(idPropietario.toString().getBytes().length);
					out.write(idPropietario.toString().getBytes());
					out.flush();
					out.writeInt(confidencialidad2.getBytes().length);
					out.write(confidencialidad2.getBytes());
					out.flush();

					DataInputStream input = new DataInputStream(client2.getInputStream());
					ObjectInputStream input_obj= new ObjectInputStream(input);
					
					Response resp =(Response) input_obj.readObject();
					
					if (resp.getError()==0) {
						if(confidencialidad2.equals("PRIV")) {
							System.out.println("Documentos en privado:");
							for(String priv: resp.getPrivateFiles()) {
								System.out.println(priv);
								
							}
						}
						System.out.println("Documentos en publico:");
						for(String pub: resp.getPublicFiles()) {
							System.out.println(pub);
							
						}	
						
					}else {
						System.out.println(resp.getErrorMsg());
						
						
					}
			
				
					input.close();
					input_obj.close();
					out.close();

				} catch (IOException | KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}.start();








	}

}
