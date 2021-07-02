package common;

import java.security.*;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;
import java.util.ArrayList;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;


public class Encription {
	public static byte[] decriptFilePGP(byte[] encriptedKey, byte[] encriptedFile, byte[] cipherParams, String pass, String entryAlias, KeyStore keystore) throws Exception {
		//Pasamos al desencriptado
		System.out.println("Desencriptando LA CLAVE ");
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, keystore.getKey(entryAlias,pass.toCharArray()));
		byte [] clave_desencriptada=cipher.doFinal(encriptedKey);

		System.out.println("Desencriptando El Archivo ");
		SecretKey key = new SecretKeySpec(clave_desencriptada,0,clave_desencriptada.length,"AES");
		
		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		AlgorithmParameters params= AlgorithmParameters.getInstance("AES", "SunJCE");
		params.init(cipherParams);
		cipher.init(Cipher.DECRYPT_MODE, key, params);
		return cipher.doFinal(encriptedFile);
	}
	

	public static ArrayList<byte[]> encript2sendPGP(byte[] fileDecripted, PublicKey publicKey) throws Exception {
		ArrayList<byte[]> message = new ArrayList<byte[]>();
		//Generamos clave AES 128
		String algorithm= "AES";

		KeyGenerator kg= KeyGenerator.getInstance(algorithm);
		kg.init(128);
		SecretKey key= kg.generateKey();

		//Ciframos el fichero, con key sin cifrar
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte [] file_encriptado=cipher.doFinal(fileDecripted);
		
		message.add(file_encriptado);
		message.add(cipher.getParameters().getEncoded());

		cipher=Cipher.getInstance("RSA/ECB/PKCS1Padding");

		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] clave_encriptada= cipher.doFinal(key.getEncoded());


		System.out.println("TAMAÑO PAQUETE encriptado : "+ file_encriptado.length);
		message.add(clave_encriptada);
		return message;
	}
	
	public static byte[] decriptDocument(byte[] document, String keyAlias, String password, String algorithm, byte[] cipherParams, KeyStore keystore) throws Exception {
		PasswordProtection pass = new PasswordProtection(password.toCharArray());
		
		SecretKeyEntry secretKeyEntry = (SecretKeyEntry) keystore.getEntry(keyAlias, pass);
		SecretKey keyPrivate = secretKeyEntry.getSecretKey();
		
		String concat= algorithm+"/CBC/PKCS5Padding";
		Cipher cipher_private = Cipher.getInstance(concat);
		
		AlgorithmParameters params= AlgorithmParameters.getInstance(algorithm, "SunJCE");
		params.init(cipherParams);
		
		cipher_private.init(Cipher.DECRYPT_MODE, keyPrivate,params);
		return cipher_private.doFinal(document);
	}
	
	public static ArrayList<byte[]> encriptDocument(byte[] document, String keyAlias, String password, String algorithm, KeyStore keystore) throws Exception {
		ArrayList<byte[]> tuple = new  ArrayList<byte[]>();
		PasswordProtection pass = new PasswordProtection(password.toCharArray());
		SecretKeyEntry secretKeyEntry = (SecretKeyEntry) keystore.getEntry(keyAlias, pass);
		SecretKey keyPrivate = secretKeyEntry.getSecretKey();
		System.out.println("FORMATO clave de encriptado de info en el server : "+keyPrivate.getFormat());

		//Ciframos el fichero
		String concat= algorithm+"/CBC/PKCS5Padding";
		Cipher cipher_private = Cipher.getInstance(concat); 
		cipher_private.init(Cipher.ENCRYPT_MODE, keyPrivate);
		
		tuple.add(cipher_private.getParameters().getEncoded());
		tuple.add(cipher_private.doFinal(document));

		return tuple;
	}
	
}
