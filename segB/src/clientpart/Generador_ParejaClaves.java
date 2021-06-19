package clientpart;




import java.security.cert.X509Certificate;

import es.mityc.javasign.certificate.CertStatusException;
import es.mityc.javasign.certificate.ICertStatus;
import es.mityc.javasign.certificate.ICertStatusRecoverer;

/**
 * <p>
 * Clase de ejemplo para la validaci�n b�sica (es decir, s�lo se valida el
 * certificado, no toda la ruta de certificaci�n) de un certificado contra un
 * servidor OCSP utilizando la librer�a OCSP.
 * </p>
 * <p>
 * La configuraci�n de la red a utilizar (si se usa proxy o no) vienen dados por
 * las constantes definidas en la clase padre <code>BaseOCSPValidation</code>
 * </p>
 * <p>
 * La configuraci�n del certificado a validar y el OCSP a utilizar, para
 * simplificar el c�digo del programa, viene dado por una serie de constantes.
 * Las constantes usadas, y que pueden ser modificadas seg�n las necesidades
 * espec�ficas, son las siguientes:
 * </p>
 * <ul>
 * <li><code>OCSP_RESPONDER</code></li>
 * <li><code>CERTIFICATE_TO_CHECK</code></li>
 * </ul>
 * 
 */
public class BasicOCSPValidation extends BaseOCSPValidation {

    /**
     * <p>
     * Direcci�n del servidor OCSP a utilizar para realizar la validaci�n
     * </p>
     */
    private final static String OCSP_RESPONDER = "";

    /**
     * <p>
     * Recurso que se corresponde con el certificado cuyo estado se desea
     * comprobar
     * </p>
     */
    private final static String CERTIFICATE_TO_CHECK = "/usr0061.cer";

    /**
     * <p>
     * Punto de entrada al programa
     * </p>
     * 
     * @param args
     *            Argumentos del programa
     */
    public static void main(String[] args) {
        BasicOCSPValidation basicOCSPValidation = new BasicOCSPValidation();
        basicOCSPValidation.execute();
    }

    @Override
    protected String getCertificateToCheck() {
        return CERTIFICATE_TO_CHECK;
    }

    @Override
    protected String getOCSPResponder() {
        return OCSP_RESPONDER;
    }

    @Override
    protected void doOCSPValidation(X509Certificate certificate, 
            ICertStatusRecoverer certStatusRecoverer) {

        // Estructura que almacenar� la respuesta del servidor OCSP
        ICertStatus certStatus = null;
            // Se realiza la consulta
        try {
        	certStatus = certStatusRecoverer.getCertStatus(certificate);
        } catch (CertStatusException e) {
            System.err.println("Error al comprobar el estado del certificado");
            e.printStackTrace();
            System.exit(-1);
        }
        
        if (certStatus != null) {
            switch (certStatus.getStatus()) {
            case valid:
                System.out.println("El certificado consultado es v�lido.");
                break;
            case revoked:
                System.out.println("El certificado consultado fue revocado el " + 
                certStatus.getRevokedInfo().getRevokedDate() + ".");
                break;
            default:
                System.out.println("Se desconoce el estado del certificado.");
            }
        } else {
            System.out.println("Hubo un error al contactar con el servidor OCSP " + getOCSPResponder());
        }
    }
}