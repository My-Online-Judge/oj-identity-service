package vn.thanhtuanle.user;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Handles come from the Google display name (Q1), never the email, and always fit the username rule. */
class UserHandlesTest {

    private static final Pattern USERNAME_RULE = Pattern.compile("^[a-zA-Z0-9_]{3,32}$");

    @ParameterizedTest(name = "\"{0}\" -> \"{1}\"")
    @CsvSource(delimiter = '|', emptyValue = "", nullValues = "NULL", value = {
            "Nguyễn Văn A          | nguyen_van_a",
            "Tuấn Lê               | tuan_le",
            "Đức                   | duc",
            "ĐẶNG Thị Ngọc Ánh     | dang_thi_ngoc_anh",
            "Phạm Thùy Dương       | pham_thuy_duong",
            "Nguyen.Van-A+oj       | nguyen_van_a_oj",
            "a_b__c                | a_b_c",
            "_x_y_                 | x_y",
            "ab                    | user_ab",
            "Lê                    | user_le",
            "Zoë Smith-Jones       | zoe_smith_jones",
            "R2-D2                 | r2_d2",
            "\u00D0\u1EB7ng V\u0103n A   | dang_van_a",
            "Gu\u00F0r\u00FAn               | gudrun",
            "\uFF21\uFF4C\uFF49\uFF43\uFF45           | alice",
            "\uFB01ona                | fiona",
            "\u0141ukasz \u017B\u00F3\u0142\u0107    | lukasz_zolc",
            "S\u00F8ren                | soren",
            "Stra\u00DFe               | strasse",
            "\u00C6sir \u0152uvre       | aesir_oeuvre",
            "\u00DE\u00F3r                | thor",
            "Y\u0131ld\u0131z             | yildiz",
            "\uD835\uDC13\uD835\uDC2E\uD835\uDC1A\uD835\uDC27 | tuan",
            "\u210C\u212Fllo \uD835\uDD7F\uD835\uDD94   | hello_to",
            "\u0110\u1EE8C \u01A0N \u01AF\u1EDANG  | duc_on_uong",
            "\u00D0\u0141\u00D8 \u1E9E\u00C6\u0152\u00DE | dlo_ssaeoeth",
            "\u0130stanbul           | istanbul",
            "..                    | ''",
            "'   '                 | ''",
            "李小龙                  | ''",
            "NULL                  | ''",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaa_b            | aaaaaaaaaaaaaaaaaaaaaaaaaaa",
    })
    void theBaseOfADisplayName(String name, String expected) {
        assertThat(UserHandles.base(name)).isEqualTo(expected);
    }

    @Test
    void theCutsAreTheRulesLength() {
        assertThat(UserHandles.base("a".repeat(40))).hasSize(UserHandles.MAX_BASE);
        assertThat(UserHandles.candidate(UserHandles.base("a".repeat(40)), UserHandles.MAX_SUFFIX)).hasSize(32);
    }

    @Test
    void candidatesAreTheBaseThenNumbered() {
        assertThat(UserHandles.candidate("alice", 1)).isEqualTo("alice");
        assertThat(UserHandles.candidate("alice", 2)).isEqualTo("alice_2");
        assertThat(UserHandles.candidate("alice", 999)).isEqualTo("alice_999");
    }

    @Test
    void theRandomFallbackKeeps23CharactersAnd8Hex() {
        String base = "abcdefghijklmnopqrstuvwxyz01";

        String handle = UserHandles.randomFallback(base, new Random(42));

        assertThat(handle).hasSize(23 + 1 + 8).matches("^[a-z0-9_]{32}$").startsWith(base.substring(0, 23) + "_");
        assertThat(handle.substring(24)).matches("[0-9a-f]{8}");
        assertThat(UserHandles.randomFallback("alice", new Random(42))).matches("alice_[0-9a-f]{8}");
    }

    @Test
    void aNameWithNothingUsableIsUserAnd6Hex() {
        assertThat(UserHandles.anonymous(new Random(7))).matches("user[0-9a-f]{6}");
    }

    @Test
    void theHandleMatchesTheUsernameRule() {
        Random random = new Random(20261021);
        List<String> names = new ArrayList<>(List.of("", " ", "@", "_", "__a__", "a", "đ", "Ǆ", "ﬁ", "İ"));
        String punctuation = " .,-_+@'\"!?#$%&*()[]{}<>/\\|~`^=:;\t\n";
        while (names.size() < 500) {
            StringBuilder name = new StringBuilder();
            int length = random.nextInt(45);
            for (int i = 0; i < length; i++) {
                switch (random.nextInt(4)) {
                    case 0 -> name.append(punctuation.charAt(random.nextInt(punctuation.length())));
                    case 1 -> name.append((char) ('A' + random.nextInt(58)));
                    case 2 -> name.appendCodePoint(0xC0 + random.nextInt(0x1EF9 - 0xC0));
                    default -> name.appendCodePoint(random.nextInt(Character.MAX_CODE_POINT + 1));
                }
            }
            names.add(name.toString());
        }

        int withNothingUsable = 0;
        for (String name : names) {
            String base = UserHandles.base(name);
            List<String> handles = new ArrayList<>();
            if (base.isEmpty()) {
                withNothingUsable++;
                handles.add(UserHandles.anonymous(random));
                handles.add(UserHandles.randomFallback("user", random));
            } else {
                assertThat(base).as(name).hasSizeLessThanOrEqualTo(UserHandles.MAX_BASE);
                for (int n : new int[] {1, 2, UserHandles.MAX_SUFFIX}) {
                    handles.add(UserHandles.candidate(base, n));
                }
                handles.add(UserHandles.randomFallback(base, random));
            }
            for (String handle : handles) {
                assertThat(handle).as("from \"%s\"", name).matches(USERNAME_RULE);
            }
        }
        assertThat(withNothingUsable).as("the corpus covers names with nothing usable").isPositive();
    }

    @Test
    void aTakenHandleGetsTheNextNumber() {
        Set<String> taken = Set.of("alice", "alice_2");

        assertThat(UserHandles.allocate("Alice", taken::contains, new Random(1))).isEqualTo("alice_3");
    }

    @Test
    void whenEveryNumberIsTakenTheRandomFallbackIsTried() {
        Set<String> taken = new HashSet<>();
        for (int n = 1; n <= UserHandles.MAX_SUFFIX; n++) {
            taken.add(UserHandles.candidate("alice", n));
        }

        assertThat(UserHandles.allocate("Alice", taken::contains, new Random(1))).matches("alice_[0-9a-f]{8}");
        assertThatThrownBy(() -> UserHandles.allocate("Alice", handle -> true, new Random(1)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aNameWithNothingUsableGetsUserAndRandomHex() {
        assertThat(UserHandles.allocate("…", handle -> false, new Random(1))).matches("user[0-9a-f]{6}");
        // That one taken: the random fallback of "user".
        assertThat(UserHandles.allocate(null, handle -> handle.length() == 10, new Random(1)))
                .matches("user_[0-9a-f]{8}");
    }

    @Test
    void theSourceIsTheDisplayNameNeverTheEmail() {
        assertThat(HandleAllocator.sourceOf("Nguyen.Van.A@gmail.com", "Nguyễn Văn A")).isEqualTo("Nguyễn Văn A");
        assertThat(HandleAllocator.sourceOf("alice@example.com", null)).isEmpty();
        assertThat(HandleAllocator.sourceOf("alice@example.com", "  ")).isEmpty();
    }

    /** Some Google accounts carry an address as their name: that part never becomes a public handle. */
    @Test
    void anEmailInTheDisplayNameIsLeftOut() {
        assertThat(UserHandles.base(HandleAllocator.sourceOf("x@gmail.com", "john.doe@gmail.com"))).isEmpty();
        assertThat(UserHandles.base(HandleAllocator.sourceOf("x@gmail.com", "John Doe (john.doe@gmail.com)")))
                .isEqualTo("john_doe");
        assertThat(UserHandles.base(HandleAllocator.sourceOf("x@gmail.com", "Mai a@b.c d@e Lan")))
                .isEqualTo("mai_lan");
        assertThat(UserHandles.allocate(HandleAllocator.sourceOf("x@gmail.com", "john.doe@gmail.com"),
                handle -> false, new Random(1))).matches("user[0-9a-f]{6}");
    }

    /** A look-alike at sign (fullwidth or small) still marks an address, which is left out like any other. */
    @Test
    void anEmailWithALookAlikeAtSignIsLeftOutToo() {
        assertThat(UserHandles.base(HandleAllocator.sourceOf("x@gmail.com", "john.doe\uFF20gmail.com"))).isEmpty();
        assertThat(UserHandles.base(HandleAllocator.sourceOf("x@gmail.com", "Mai Lan (mai\uFE6Bexample.com)")))
                .isEqualTo("mai_lan");
        assertThat(UserHandles.base(HandleAllocator.sourceOf("x@gmail.com", "\uFF2A\uFF4F\uFF48\uFF4E\u3000"
                + "j\uFF20x\uFF0Ecom"))).isEqualTo("john");
    }
}
