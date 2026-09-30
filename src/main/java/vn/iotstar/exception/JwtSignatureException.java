package vn.iotstar.exception;

public class JwtSignatureException extends JwtInvalidException {

    public JwtSignatureException(String message) {
        super(message);
    }
}
