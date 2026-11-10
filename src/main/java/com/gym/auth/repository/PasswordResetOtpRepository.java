package com.gym.auth.repository;

import com.gym.auth.entity.PasswordResetOtp;
import jakarta.persistence.LockModeType;
import java.time.LocalDateTime;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PasswordResetOtpRepository extends JpaRepository<PasswordResetOtp, Long> {

	/** Latest OTP that has not been used or invalidated, locked for the duration of the transaction. */
	@Lock(LockModeType.PESSIMISTIC_WRITE)
	Optional<PasswordResetOtp> findFirstByUserIdAndUsedAtIsNullOrderByOtpIdDesc(Long userId);

	Optional<PasswordResetOtp> findFirstByUserIdOrderByOtpIdDesc(Long userId);

	long countByUserIdAndCreatedAtAfter(Long userId, LocalDateTime since);

	@Lock(LockModeType.PESSIMISTIC_WRITE)
	@Query("select o from PasswordResetOtp o where o.otpId = :otpId")
	Optional<PasswordResetOtp> findByIdForUpdate(@Param("otpId") Long otpId);

	/** Marks every still-usable OTP of the user as used, so none of them can be verified or reset with. */
	@Modifying(flushAutomatically = true)
	@Query("update PasswordResetOtp o set o.usedAt = :now where o.userId = :userId and o.usedAt is null")
	int invalidateActiveOtps(@Param("userId") Long userId, @Param("now") LocalDateTime now);

}
