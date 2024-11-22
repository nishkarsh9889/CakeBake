package com.cakebake.project.Repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.cakebake.project.Model.User;

public interface UserRepo extends JpaRepository<User, Integer> {
    Optional<User> findUserByEmail(String email);
}
