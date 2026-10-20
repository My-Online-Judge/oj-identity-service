package vn.thanhtuanle.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import vn.thanhtuanle.auth.dto.IntrospectRequest;
import vn.thanhtuanle.common.enums.TokenType;
import vn.thanhtuanle.common.util.JwtUtil;
import vn.thanhtuanle.entity.Token;
import vn.thanhtuanle.repository.TokenRepository;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceIntrospectTest {

    @Mock
    private JwtUtil jwtUtil;
    @Mock
    private TokenRepository tokenRepository;
    @InjectMocks
    private AuthService authService;

    @Test
    void introspect_looksUpTheHashNotTheRawToken() {
        String raw = "header.payload.sig";
        when(jwtUtil.isTokenExpired(raw)).thenReturn(false);
        when(tokenRepository.findByToken(TokenHasher.sha256Hex(raw))).thenReturn(Optional.of(
                Token.builder().token(TokenHasher.sha256Hex(raw)).tokenType(TokenType.ACCESS).build()));

        var response = authService.introspect(new IntrospectRequest(raw, TokenType.ACCESS));

        assertThat(response.isValid()).isTrue();
        verify(tokenRepository, never()).findByToken(raw);
    }
}
