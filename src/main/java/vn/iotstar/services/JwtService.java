package vn.iotstar.services;

import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import vn.iotstar.exception.JwtExpiredException;
import vn.iotstar.exception.JwtInvalidException;
import vn.iotstar.exception.JwtSignatureException;

@Service
public class JwtService {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    public String extractUsername(String token) {
        return extractClaim(token, JWTClaimsSet::getSubject);
    }

    public <T> T extractClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
        final JWTClaimsSet claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        long now = System.currentTimeMillis();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        extraClaims.forEach(builder::claim);
        JWTClaimsSet claimsSet = builder
                .subject(userDetails.getUsername())
                .issueTime(new Date(now))
                .expirationTime(new Date(now + expiration))
                .jwtID(UUID.randomUUID().toString())
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

        try {
            signedJWT.sign(new MACSigner(getSignInKey()));
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot sign JWT", e);
        }

        return signedJWT.serialize();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, JWTClaimsSet::getExpirationTime);
    }

    private JWTClaimsSet extractAllClaims(String token) {
        SignedJWT signedJWT;

        try {
            signedJWT = SignedJWT.parse(token);
        } catch (ParseException e) {
            throw new JwtInvalidException("Malformed JWT", e);
        }

        try {
            boolean validAlgorithm = JWSAlgorithm.HS256.equals(signedJWT.getHeader().getAlgorithm());

            if (!validAlgorithm || !signedJWT.verify(new MACVerifier(getSignInKey()))) {
                throw new JwtSignatureException("JWT signature does not match locally computed signature");
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            Date expiration = claims.getExpirationTime();

            if (expiration == null) {
                throw new JwtInvalidException("JWT has no expiration time");
            }

            if (expiration.before(new Date())) {
                throw new JwtExpiredException("JWT expired at " + expiration);
            }

            return claims;
        } catch (JOSEException | ParseException e) {
            throw new JwtInvalidException("Invalid JWT", e);
        }
    }

    private byte[] getSignInKey() {
        return Base64.getDecoder().decode(secretKey);
    }
}
