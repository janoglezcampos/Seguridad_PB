
# Lista de tareas:

## Hanshake:
* ~~Mutual handhake~~  :white_check_mark:
* ~~OCSP~~ :white_check_mark:
* ~~Habilitar ciphersuits sin cifrado~~ :white_check_mark:
* ~~Mostrar solo ciphersuits sin cifrado~~ :white_check_mark:

## Certificados
* ~~Firmar cerificados con propia CA~~ :white_check_mark:
* ~~Cambiar jks a jceks~~  :white_check_mark:
* ~~Añadir clave simetrica para encriptado local en el servidor~~ :white_check_mark:
* Encadenar certificados con certificado de la ca

## Funcionalidad 1:
* ~~Generar respuestas serverside (server)~~ :white_check_mark:
* ~~Validar CertFirmaC (server)~~ :white_check_mark:
* ~~Almacenar clave pública del cliente (CertCifrado_c) para posterior cifrado (server)~~ :white_check_mark:
* ~~Envío cifrado al cliente~~ :white_check_mark:
* Almacenar todo en un fichero, no en un directorio (server)
* Validar CertFirmaS (cliente)
* Verificar firma al recibir ok (cliente)
* Eliminar archivo enviado (cliente)
* Guardar hash archivo enviado y asociarlo al idRegistro (cliente)
* Comprobar hash al recibir archivo (cliente)

## Funcionalidad 2:
* Generar respuestas serverside (server)
* Enviar certAuth y no issuerDN (cliente)
* Validar certAuth (server)
* Obtener issuerDN del certAuth (server)
* Enviar datos como una lista (server)


## Funcionalidad 3:
* ~~Desecriptar archivo con clave secreta simetrica (server)~~  :white_check_mark:
* ~~Encriptar con PGP (server)~~  :white_check_mark:
* ~~Desecriptar con PGP (cliente)~~ :white_check_mark:
* Comprobar si existe el documento (server)
* Validar certAuth (server)
* Generar respuestas serverside (server)
* Enviar nombre del archivo (server)
* Guardar con nombre del archivo (cliente)
* Validar CertFirmaS (cliente)
* Verificar certificado de firma_s (cliente)
* Comprobar que sigRD es válida (cliente)
* Computar hash y comparar con el almacenado en Funcionalidad 1 (cliente)

## Opcional:
* Crear una base de datos, aunque sea txt, y no depender de las listas (para permitir cerrar y reabrir cliente).
* Mejorar codigo, POO
