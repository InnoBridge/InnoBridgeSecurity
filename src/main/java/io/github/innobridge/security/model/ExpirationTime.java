package io.github.innobridge.security.model;

import lombok.Data;

@Data
public class ExpirationTime {
    private final int days;
    private final int hours;
    private final int minutes;
    private final int seconds;

    public ExpirationTime(int days, int hours, int minutes, int seconds) {
        this.days = days;
        this.hours = hours;
        this.minutes = minutes;
        this.seconds = seconds;
    }

    public long toSeconds() {
        return ((days * 24L + hours) * 60 + minutes) * 60 + seconds;
    }

    public long toMillis() {
        return toSeconds() * 1000;
    }
}
