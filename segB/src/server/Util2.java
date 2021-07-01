package server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.ArrayList;
import common.Response;



public class Util2 {

	static ArrayList <String> privado = new ArrayList <String>();
	static ArrayList <String> publico = new ArrayList <String>();
	
	
	
	private static String savePath="C:\\Users\\usuario\\Desktop\\SEG-LEXY/serverSavedFiles/";

	public static void start(Socket aClient) {
		new Thread() {
			public void run() {
				try {
					DatabaseEntry data;
					Response resp;
					DataInputStream input= new DataInputStream(aClient.getInputStream());
					String id_Propetario= new String (input.readNBytes(input.readInt()));
					String confidencialidad=new String(input.readNBytes(input.readInt()));
					ArrayList<ArrayList<String>> complete = new ArrayList<ArrayList<String>>();
					
					privado.clear();
					publico.clear();
					
					complete=DatabaseEntry.getFiles(savePath, id_Propetario);

					DataOutputStream out = new DataOutputStream(aClient.getOutputStream());
					ObjectOutputStream out_obj= new ObjectOutputStream(out);
					
					//contains con cada elemento y hacer el .flush

					if (confidencialidad.equals("PUB")|| confidencialidad.equals("PRIV")) {     
						if (confidencialidad.equals("PRIV")) {
							System.out.println("EL usuario tiene"+complete.get(1).size() +"documentos en privado");
							for (String file: complete.get(1)) {
								
									data=DatabaseEntry.recoverEntry(savePath,file);
									privado.add(data.getInfo());	
									
							}
							
							System.out.println("Hay "+complete.get(0).size() +"documentos en público");
							for (String file: complete.get(0)) {
								
									data=DatabaseEntry.recoverEntry(savePath,file);
									publico.add(data.getInfo());	
									
							}
							
							resp=new Response(publico, privado);
							out_obj.writeObject(resp);
			
						}
						else if (confidencialidad.equals("PUB")) {
							
							System.out.println("Hay "+complete.get(0).size() +"documentos en público");
							for (String file: complete.get(0)) {
								
								data=DatabaseEntry.recoverEntry(savePath,file);
								publico.add(data.getInfo());
								privado.clear();
									
							}
							resp=new Response(publico, privado);
							out_obj.writeObject(resp);
							
						}
					}
					else {
						resp= new Response(-6);
						out_obj.writeObject(resp);
					}
					//output.println("\n HAY DOCUMENTOS"); //cambiar
					out.close();
					out_obj.close();

				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}.start();
	}

}