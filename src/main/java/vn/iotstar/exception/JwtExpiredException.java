package vn.iotstar.exception;

public class JwtExpiredException extends JwtInvalidException {

    public JwtExpiredException(String message) {
        super(message);
    }
}
