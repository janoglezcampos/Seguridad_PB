# Lista de tareas:

__Problema en el enunciado!__
* -> PROBLEMA CON EL ENUNCIADO!!
							 
Entiendo que si un archivo es público, es porque queremos compartirlo con
otros cliente pero... 
Si SigRD = SigR(idRegistro,selloTemporal,idPropietario,documento,firmaDoc) 
y firmaDoc = Sigpropietario(documento), y como la respuesta de recuperacion 
de archivo: (0,tipoConfidencialidad,idRegistro,idPropietario,selloTemporal,EPKC
(K),EK(documento),SigRD,CertFirm ), no incluye firmaDoc, significa que para
comprobar sigRD del lado del cliente para validarla, debes calcularla, pero
es necesario dirmaDoc, y para calcular esta es necesaria la clave privada del
cliente propietario que obviamente no tenemos, por lo tanto es imposible que
se pueda validar SigRD desde un cliente que no sea el propietario original.
							  
Además un cliente no tiene por qué conocer el hash de un archivo subido por
otro cliente.
							  
Para solucionarlo, aunque no es buena idea en un sistema real, se elimina la
necesidad de validación de sigRD si el archivo es publico. En el caso del
hash, en un sistema real tampoco se podría comprobar a menos que se enviase
en la respuesta, por lo tanto tambien se ignora si es publico.

## General
* ~~Asignar rutas de guardado y alias de las claves a variables globales en servidor y cliente~~ :white_check_mark:
* Obtener tipo de algoritmo de la clave simetrica almacenana en keystore del servidor

## Hanshake:
* ~~Mutual handhake~~  :white_check_mark:
* ~~OCSP~~ :white_check_mark:
* ~~Habilitar ciphersuits sin cifrado~~ :white_check_mark:
* ~~Mostrar solo ciphersuits sin cifrado~~ :white_check_mark:

## Certificados
* ~~Firmar cerificados con propia CA~~ :white_check_mark:
* ~~Cambiar jks a jceks~~  :white_check_mark:
* ~~Añadir clave simetrica para encriptado local en el servidor~~ :white_check_mark:
* ~~Encadenar certificados con certificado de la ca~~

## Funcionalidad 1:
* ~~Generar respuestas serverside (server)~~ :white_check_mark:
* ~~Validar CertFirmaC (server)~~ :white_check_mark:
* ~~Almacenar clave pública del cliente (CertCifrado_c) para posterior cifrado (server)~~ :white_check_mark:
* ~~Envío cifrado al cliente~~ :white_check_mark:
* ~~Validar CertFirmaS (cliente)~~ :white_check_mark:
* ~~Verificar firma al recibir ok (cliente)~~ :white_check_mark:
* ~~Guardar hash archivo enviado y asociarlo al idRegistro (cliente)~~ :white_check_mark:
* ~~Almacenar todo en un fichero, no en un directorio (server)~~ :white_check_mark:
* ~~Eliminar archivo enviado (cliente)~~ :white_check_mark:
* Reescribir hashes en el txt cuando se repite idRegistor

## Funcionalidad 2:
* ~~Generar respuestas serverside (server)~~
* ~~Enviar certAuth y no issuerDN (cliente)~~
* ~~Validar certAuth (server)~~
* ~~Obtener issuerDN del certAuth (server)~~
* ~~Enviar datos como una lista (server)~~


## Funcionalidad 3:
* ~~Desecriptar archivo con clave secreta simetrica (server)~~  :white_check_mark:
* ~~Encriptar con PGP (server)~~  :white_check_mark:
* ~~Desecriptar con PGP (cliente)~~ :white_check_mark:
* ~~Comprobar si existe el documento (server)~~ :white_check_mark:
* ~~Validar certAuth (server)~~ :white_check_mark:
* ~~Generar respuestas serverside (server)~~ :white_check_mark:
* ~~Enviar nombre del archivo (server)~~ :white_check_mark:
* ~~Validar CertFirmaS (cliente)~~ :white_check_mark:
* ~~Verificar certificado de firma_s (cliente)~~ :white_check_mark:
* ~~Comprobar que sigRD es válida (cliente)~~ :white_check_mark:
* ~~Computar hash y comparar con el almacenado en Funcionalidad 1 (cliente)~~ :white_check_mark:
* ~~Enviar nombre del documento (servidor)~~
* ~~Guardar con nombre del documento (cliente)~~
* ~~Modificar para que cualquiera pueda acceder a los archivos publicos (server)~~


## Opcional:
* ~~Crear una base de datos, aunque sea txt, y no depender de las listas (para permitir cerrar y reabrir cliente).~~ :white_check_mark:
* Mejorar codigo, POO

## [Archivos: almacenes y CA](https://drive.google.com/drive/folders/1lCv0Sylmk9a1QR4UhN9tw8FaoDe6kHwd?usp=sharing)

