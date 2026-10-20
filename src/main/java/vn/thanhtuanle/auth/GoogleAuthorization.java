package vn.thanhtuanle.auth;

/**
 * One Google sign-in attempt: the URL the browser goes to, plus the three values only the callback may see. The
 * {@code state} defends the callback against CSRF, the {@code codeVerifier} is the PKCE secret whose S256 challenge is
 * in the URL, and the {@code nonce} must come back inside the id token.
 */
public record GoogleAuthorization(String url, String state, String codeVerifier, String nonce) {
}
