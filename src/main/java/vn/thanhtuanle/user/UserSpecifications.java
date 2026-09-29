package vn.thanhtuanle.user;

import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;
import org.springframework.data.jpa.domain.Specification;
import vn.thanhtuanle.common.enums.UserStatus;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.entity.User;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Dynamic filters for the admin user list. Building predicates only for the filters actually
 * supplied avoids the "{@code :param IS NULL OR col = :param}" pattern that breaks on
 * PostgreSQL (it cannot infer the type of a NULL bind parameter).
 */
public final class UserSpecifications {

    private UserSpecifications() {
    }

    public static Specification<User> filter(String search, Integer status, UUID roleId,
            LocalDate createdFrom, LocalDate createdTo) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (search != null && !search.isBlank()) {
                String like = "%" + search.trim().toLowerCase() + "%";
                predicates.add(cb.or(
                        cb.like(cb.lower(root.get("username")), like),
                        cb.like(cb.lower(root.get("email")), like),
                        cb.like(cb.lower(root.get("name")), like)));
            }

            if (status != null) {
                predicates.add(cb.equal(root.get("status"), status));
            } else {
                // Hide soft-deleted users unless a status is explicitly requested.
                predicates.add(cb.notEqual(root.get("status"), UserStatus.DELETED.getValue()));
            }

            if (roleId != null) {
                // Subquery (not a join) so pagination stays correct against the EAGER roles.
                Subquery<UUID> sub = query.subquery(UUID.class);
                Root<User> subRoot = sub.from(User.class);
                Join<User, Role> roleJoin = subRoot.join("roles");
                sub.select(subRoot.get("id")).where(cb.equal(roleJoin.get("id"), roleId));
                predicates.add(root.get("id").in(sub));
            }

            if (createdFrom != null) {
                predicates.add(cb.greaterThanOrEqualTo(
                        root.<LocalDateTime>get("createdAt"), createdFrom.atStartOfDay()));
            }
            if (createdTo != null) {
                predicates.add(cb.lessThan(
                        root.<LocalDateTime>get("createdAt"), createdTo.plusDays(1).atStartOfDay()));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}
