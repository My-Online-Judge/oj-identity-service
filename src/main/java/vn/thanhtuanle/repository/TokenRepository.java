package vn.thanhtuanle.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import vn.thanhtuanle.common.enums.TokenType;
import vn.thanhtuanle.entity.Token;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TokenRepository extends JpaRepository<Token, UUID> {
    @Query(value = """
            select t from Token t inner join User u\s
            on t.user.id = u.id\s
            where u.id = :id and (t.expired = false or t.revoked = false)\s
            """)
    List<Token> findAllValidTokenByUser(UUID userId);

    /** {@code token} is the SHA-256 hex of the presented token ({@link vn.thanhtuanle.auth.TokenHasher}). */
    Optional<Token> findByToken(String token);

    void deleteAllByUserId(UUID userId);

    void deleteAllByUserIdAndTokenType(UUID userId, TokenType tokenType);

    @Modifying
    @Query("update Token t set t.rotatedAt = :now where t.id = :id and t.rotatedAt is null")
    int markRotated(UUID id, LocalDateTime now);

    @Modifying
    @Query("delete from Token t where t.user.id = :userId and t.rotatedAt < :before")
    int deleteRotatedBefore(UUID userId, LocalDateTime before);
}
