package server;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;

public class Util2 {

	static ArrayList <String> privado = new ArrayList <String>();
	static ArrayList <String> publico = new ArrayList <String>();
	
	private static String savePath="/Users/lexy/Desktop/Clases/Seguridad/serverSavedFiles/";

	public static void start(Socket aClient) {
		new Thread() {
			public void run() {
				try {/*
					privado.clear();
					publico.clear();
					DataInputStream input= new DataInputStream(aClient.getInputStream());
					String name_file= new String (input.readNBytes(input.readInt()));
					String confidencialidad=new String(input.readNBytes(input.readInt()));

					//System.out.println(name_file+" prueba "+Util.getPrivado());

					PrintWriter output = new PrintWriter(aClient.getOutputStream());
					//contains con cada elemento y hacer el .flush

					if (confidencialidad.equals("PUB")|| confidencialidad.equals("PRIV")) {     
						if (confidencialidad.equals("PRIV")) {
							for (int i=0; i<Util.getPrivado().size();i ++) {
								if( Util.getPrivado().get(i).contains(name_file)) {
									System.out.println("EL usuario tiene documentos en privado");
									privado.add(Util.getPrivado().get(i));
									System.out.println(Util.getPrivado().get(i));
								}
							}

							for (int i=0; i<privado.size(); i++) {
								ArrayList <String> respuesta = new ArrayList <String> ();
								respuesta=info(privado.get(i));
								output.println(name_file);
								output.println(respuesta.get(2));
								output.println(respuesta.get(0));
								output.println(respuesta.get(1));
							}

						}
						else if (confidencialidad.equals("PUB")) {
							for (int i=0; i<Util.getPublico().size();i ++) {
								if( Util.getPublico().get(i).contains(name_file)) {
									System.out.println("EL usuario tiene documentos en p�blico");
									publico.add(Util.getPublico().get(i));
									System.out.println(Util.getPublico().get(i));
								}
							}
							for (int i=0; i<publico.size(); i++) {
								ArrayList <String> respuesta = new ArrayList <String> ();
								respuesta=info(publico.get(i));
								output.println(name_file);
								output.println(respuesta.get(2));
								output.println(respuesta.get(0));
								output.println(respuesta.get(1));
							}
						}
						else {
							System.out.println("EL usuario  no tiene documentos");  
							output.println("\nCERTIFICADO INCORRECTO");
						}
					}
					else {
						System.out.println("Confidencialidad incorrecta");
					}
					//output.println("\n HAY DOCUMENTOS"); //cambiar
					output.close();
*/
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}.start();
	}

	public static  ArrayList<String> info (String ubicacion) throws IOException {

		ArrayList <String> conjunto = new ArrayList <String> ();
		String directorio= savePath+ubicacion;
		String sello= directorio+"/selloTemporal";
		String id= directorio+"/idRegistro";
		File directorio2 = new File(directorio); 

		ArrayList <String>  names = new ArrayList <String>();	
		String [] names2= {"confidencialidad","firmaDocumento","idRegistro","selloTemporal","firmaSigRD"};
		for (int k=0; k<names2.length;k++) {
			names.add(names2[k]);
		}

		File carpeta= new File (sello);
		FileInputStream read = new FileInputStream(carpeta);
		String sello_def= new String (read.readAllBytes());
		read.close();
		conjunto.add(sello_def);

		File [] contenido =directorio2.listFiles();

		ArrayList <String>  contenido2 = new ArrayList <String>();	

		for(int i=0; i<contenido.length; i++) {
			contenido2.add(contenido[i].getName());
		}

		for (int i=0; i< contenido2.size(); i ++) {

			if (!names.contains(contenido2.get(i))) {
				conjunto.add(contenido2.get(i));
			}
		}

		File carpeta2= new File (id);
		FileInputStream read2 = new FileInputStream(carpeta2);
		String id2= new String (read2.readAllBytes());
		read2.close();
		conjunto.add(id2);

		return conjunto;
	}
}
