package db.migration;

import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vn.thanhtuanle.user.HandleAllocator;
import vn.thanhtuanle.user.UserHandles;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Gives every live account whose username is an email address (a Google sign-up from before handles) the handle a
 * sign-up gets now: {@link UserHandles#allocate} on {@link HandleAllocator#sourceOf}, the display name. Oldest account
 * first, one row at a time, so a later row sees an earlier one's handle and the oldest gets the bare base.
 *
 * <p>Static code only, no Spring beans. Soft-deleted rows are left as they are, and a database with no live
 * email-shaped username changes nothing. No DDL.
 */
public class V8__user_handles extends BaseJavaMigration {

    private static final Logger log = LoggerFactory.getLogger(V8__user_handles.class);

    private record Row(UUID id, String username, String email, String name) {
    }

    @Override
    public void migrate(Context context) throws Exception {
        Connection connection = context.getConnection();
        List<Row> rows = new ArrayList<>();
        try (PreparedStatement select = connection.prepareStatement("""
                SELECT id, username, email, name FROM public.t_users
                WHERE status <> 2 AND username LIKE '%@%' ORDER BY created_at, id""");
             ResultSet rs = select.executeQuery()) {
            while (rs.next()) {
                rows.add(new Row(rs.getObject("id", UUID.class), rs.getString("username"), rs.getString("email"),
                        rs.getString("name")));
            }
        }

        SecureRandom random = new SecureRandom();
        try (PreparedStatement taken = connection.prepareStatement(
                     "SELECT 1 FROM public.t_users WHERE status <> 2 AND lower(username) = ?");
             PreparedStatement update = connection.prepareStatement(
                     "UPDATE public.t_users SET username = ?, updated_at = now(), updated_by = 'V8' WHERE id = ?")) {
            for (Row row : rows) {
                String source = HandleAllocator.sourceOf(row.email() != null ? row.email() : row.username(), row.name());
                String handle = UserHandles.allocate(source, candidate -> isTaken(taken, candidate), random);
                update.setString(1, handle);
                update.setObject(2, row.id());
                update.executeUpdate();
            }
        }
        log.info("V8: {} email usernames replaced by handles", rows.size());
    }

    /** Whether a live account has this handle; handles are lower case, so it is compared with {@code lower()}. */
    private static boolean isTaken(PreparedStatement taken, String handle) {
        try {
            taken.setString(1, handle);
            try (ResultSet rs = taken.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw new IllegalStateException("V8: could not check whether a handle is taken", e);
        }
    }
}
