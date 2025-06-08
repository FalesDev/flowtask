package com.falesdev.flowtask.repository.redis;

import com.falesdev.flowtask.domain.redis.Otp;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OtpRepository extends CrudRepository<Otp, String> {
}
