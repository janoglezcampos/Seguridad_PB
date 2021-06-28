TODO:
Hanshake:
* Mutual handhake - DONE
* OCSP - DONE
* Habilitar ciphersuits sin cifrado - DONE
* Mostrar solo ciphersuits sin cifrado - DONE

Certificados
* Firmar cerificados con propia CA - DONE
* Cambiar jks a jceks - DONE
* Añadir clave simetrica para encriptado local en el servidor - DONE

Funcionalidad 1:
* Generar respuestas serverside (server) - DONE
* Validar CertFirmaC (server) - DONE
* Almacenar clave pública del cliente (CertCifrado_c) para posterior cifrado (server) - DONE
* Almacenar todo en un fichero, no en un directorio (server)
* Validar CertFirmaS (cliente)
* Verificar firma al recibir ok (cliente)
* Eliminar archivo enviado (cliente)
* Guardar hash archivo enviado y asociarlo al idRegistro (cliente)
* Comprobar hash al recibir archivo (cliente)

Funcionalidad 2:
* Generar respuestas serverside (server)
* Enviar certAuth y no issuerDN (cliente)
* Validar certAuth (server)
* Obtener issuerDN del certAuth (server)
* Enviar datos como una lista (server)

Funcionalidad 3:
* Comprobar si existe el documento (server)
* Validar certAuth (server)
* Generar respuestas serverside (server)
* Desecriptar archivo con clave secreta simetrica (server) - DONE
* Encriptar con PGP (server) - DONE
* Desecriptar con PGP (cliente) - DONE
* Enviar nombre del archivo (server)
* Guardar con nombre del archivo (cliente)
* Validar CertFirmaS (cliente)
* Verificar certificado de firma_s (cliente)
* Comprobar que sigRD es válida (cliente)
* Computar hash y comparar con el almacenado en Funcionalidad 1 (cliente)

Opcional:
* Crear una base de datos, aunque sea txt, y no depender de las listas (para permitir cerrar y reabrir cliente).
* Mejorar codigo, POO
