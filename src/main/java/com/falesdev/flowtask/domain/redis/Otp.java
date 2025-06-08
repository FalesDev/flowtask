package com.falesdev.flowtask.domain.redis;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

import java.util.concurrent.TimeUnit;

@RedisHash("otp")
@Getter
@Setter
@NoArgsConstructor
public class Otp {
    @Id
    private String key;
    private String code;
    private String email;

    @TimeToLive(unit = TimeUnit.SECONDS)
    private Long ttl = 300L; // 5 minutos

    public Otp(String code, String email) {
        this.key = email;
        this.code = code;
        this.email = email;
    }
}
