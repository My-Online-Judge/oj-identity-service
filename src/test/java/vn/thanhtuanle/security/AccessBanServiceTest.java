package vn.thanhtuanle.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import vn.thanhtuanle.common.enums.BanType;
import vn.thanhtuanle.common.exception.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.entity.AccessBan;
import vn.thanhtuanle.security.dto.CreateBanRequest;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AccessBanServiceTest {

    private static final ClientMeta CALLER = new ClientMeta("9.9.9.9", "my-dev", "ua");

    @Mock AccessBanRepository repository;
    @Mock AccessBanMirror mirror;
    @InjectMocks AccessBanService service;

    private static CreateBanRequest req(String type, String value, Integer hours) {
        CreateBanRequest r = new CreateBanRequest();
        r.setType(type);
        r.setValue(value);
        r.setReason("spam");
        r.setDurationHours(hours);
        return r;
    }

    @Test
    void create_persists_andMirrors() {
        when(repository.existsByTypeAndValue(BanType.IP, "1.2.3.4")).thenReturn(false);
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        service.create(req("IP", "1.2.3.4", 24), CALLER);

        ArgumentCaptor<AccessBan> captor = ArgumentCaptor.forClass(AccessBan.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getType()).isEqualTo(BanType.IP);
        assertThat(captor.getValue().getExpiresAt()).isAfter(LocalDateTime.now().plusHours(23));
        verify(mirror).add(captor.getValue());
    }

    @Test
    void create_permanent_hasNullExpiry() {
        when(repository.existsByTypeAndValue(BanType.DEVICE, "bad-dev")).thenReturn(false);
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        service.create(req("DEVICE", "bad-dev", null), CALLER);
        ArgumentCaptor<AccessBan> captor = ArgumentCaptor.forClass(AccessBan.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getExpiresAt()).isNull();
    }

    @Test
    void duplicate_is409() {
        when(repository.existsByTypeAndValue(BanType.IP, "1.2.3.4")).thenReturn(true);
        assertThatThrownBy(() -> service.create(req("IP", "1.2.3.4", null), CALLER))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.BAN_EXISTED));
    }

    @Test
    void banningYourOwnIp_is409() {
        assertThatThrownBy(() -> service.create(req("IP", "9.9.9.9", null), CALLER))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.BAN_SELF));
    }

    @Test
    void banningYourOwnDevice_is409() {
        assertThatThrownBy(() -> service.create(req("DEVICE", "my-dev", null), CALLER))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.BAN_SELF));
    }

    @Test
    void badType_orBlankValue_is400() {
        assertThatThrownBy(() -> service.create(req("MAC", "x", null), CALLER))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.BAN_INVALID));
        assertThatThrownBy(() -> service.create(req("IP", "  ", null), CALLER))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.BAN_INVALID));
    }

    @Test
    void delete_removesRow_andMirrorEntry() {
        UUID id = UUID.randomUUID();
        AccessBan ban = AccessBan.builder().type(BanType.IP).value("1.2.3.4").build();
        when(repository.findById(id)).thenReturn(Optional.of(ban));
        service.delete(id);
        verify(repository).delete(ban);
        verify(mirror).remove(BanType.IP, "1.2.3.4");
    }

    @Test
    void delete_missing_is404() {
        UUID id = UUID.randomUUID();
        when(repository.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.delete(id))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.BAN_NOT_FOUND));
    }
}
