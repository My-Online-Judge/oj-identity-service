package vn.thanhtuanle.auth;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenHasherTest {

    @Test
    void knownVector() {
        // FIPS 180-2 test vector for SHA-256("abc").
        assertThat(TokenHasher.sha256Hex("abc"))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @Test
    void nullIsRejected() {
        assertThatThrownBy(() -> TokenHasher.sha256Hex(null)).isInstanceOf(IllegalArgumentException.class);
    }
}
