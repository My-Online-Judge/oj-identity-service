package vn.thanhtuanle.user;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.random.RandomGenerator;
import java.util.regex.Pattern;

/** Picks a free public handle for a Google account ({@link UserHandles#allocate}) among the live accounts. */
@Component
public class HandleAllocator {

    /** Anything shaped like an email address. */
    private static final Pattern EMAIL_LIKE = Pattern.compile("\\S+@\\S+");

    private final UserRepository userRepository;
    private final RandomGenerator random = new SecureRandom();

    public HandleAllocator(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * The first handle no live account has in any case: the rows V6's {@code ux_users_username_lower} covers, so a
     * soft-deleted account's username does not block it. Two sign-ups can still pick the same one at once; the index
     * refuses the second, and the caller retries.
     */
    public String allocate(String source) {
        return UserHandles.allocate(source, userRepository::existsLiveByUsername, random);
    }

    /**
     * What a handle is made from: the Google display name, or {@code ""} when it is blank (the handle is then
     * {@code user} + random hex). Never the email: a handle is public, and an address or its local part would tell
     * anyone how to reach the account's owner. {@code email} is deliberately unused, and an address inside the name
     * (some Google accounts carry theirs as their name) is left out too.
     */
    public static String sourceOf(String email, String name) {
        String withoutAddresses = name == null ? "" : EMAIL_LIKE.matcher(name).replaceAll(" ");
        return withoutAddresses.isBlank() ? "" : withoutAddresses;
    }
}
