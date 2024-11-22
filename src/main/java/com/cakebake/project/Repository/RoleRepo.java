package com.cakebake.project.Repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cakebake.project.Model.Role;

public interface RoleRepo extends JpaRepository<Role, Integer> {

}
