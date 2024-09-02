package io.github.innobridge.security.repository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Repository;
import io.github.innobridge.security.model.User;
import org.springframework.data.mongodb.core.query.Update;

@Repository
public class CustomUserRepositoryImpl implements CustomUserRepository {

    @Autowired
    private MongoTemplate mongoTemplate;

    @Override
    public User updateUser(String id, User user) {
        Query query = new Query(Criteria.where("id").is(id));
        Update update = new Update()
                .set("username", user.getUsername())
                .set("email", user.getEmail())
                .set("password", user.getPassword())
                .set("refreshToken", user.getRefreshToken())
                .set("authorities", user.getAuthorities())
                .set("accountNonExpired", user.isAccountNonExpired())
                .set("accountNonLocked", user.isAccountNonLocked())
                .set("credentialsNonExpired", user.isCredentialsNonExpired())
                .set("enabled", user.isEnabled());

        return mongoTemplate.findAndModify(
                query,
                update,
                FindAndModifyOptions.options().returnNew(true),
                User.class);
    }

    @Override
    public void updateTokens(String id, String accessToken, String refreshToken) {
        Query query = new Query(Criteria.where("id").is(id));
        Update update = new Update()
                .set("accessToken", accessToken)
                .set("refreshToken", refreshToken);
        mongoTemplate.updateFirst(query, update, User.class);
    }

    @Override
    public void updateAccessToken(String id, String accessToken) {
        Query query = new Query(Criteria.where("id").is(id));
        Update update = new Update()
                .set("accessToken", accessToken);
        mongoTemplate.updateFirst(query, update, User.class);
    }

    @Override
    public void deleteTokens(String id) {
        Query query = new Query(Criteria.where("id").is(id));
        Update update = new Update()
                .unset("accessToken")
                .unset("refreshToken");
        mongoTemplate.updateFirst(query, update, User.class);
    }
}