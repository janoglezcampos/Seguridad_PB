TODO:
Hanshake:
* Mutual handhake - DONE
* OCSP - DONE

Certificados
* Firmar cerificados con propia CA - DONE
* Cambiar jks a jceks - DONE
* Añadir clave simetrica para encriptado local en el servidor - DONE

Funcionalidad 1:
* Generar respuestas serverside (server)
* Almacenar clave pública del cliente (CertCifrado_c) para posterior cifrado (server)
* Almacenar todo en un fichero, no en un directorio (server)

Funcionalidad 2:
* Generar respuestas serverside (server)
* Enviar certAuth y no issuerDN (cliente)
* Comprobar certAuth (server)
* Obtener issuerDN del certAuth (server)
* Enviar datos como una lista (server)

Funcionalidad 3:
* Generar respuestas serverside (server)
* Desecriptar archivo con clave secreta simetrica (server) - DONE
* Encriptar con PGP (server)
* Desecriptar con PGP (cliente)
* Enviar nombre del archivo (server)
* Guardar con nombre del archivo (cliente)

Opcional:
* Crear una base de datos, aunque sea txt, y no depender de las listas (para permitir cerrar y reabrir cliente).
* Mejorar codigo, POO
