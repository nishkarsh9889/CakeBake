package com.cakebake.project.Repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Component;
import com.cakebake.project.Model.Category;

@Component
public interface CategoryRepo extends JpaRepository<Category, Integer> {

}