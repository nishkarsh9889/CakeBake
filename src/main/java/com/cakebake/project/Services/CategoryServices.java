package com.cakebake.project.Services;

import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.cakebake.project.Model.Category;
import com.cakebake.project.Repository.CategoryRepo;

@Service
public class CategoryServices {

    @Autowired
    private CategoryRepo categoryRepo;

    public void addCategory(Category category) {
        categoryRepo.save(category);
    }

    public List<Category> getAllCategories() {
        return categoryRepo.findAll();
    }

    public void removeCategoriesById(int id) {
        categoryRepo.deleteById(id);
    }

    public Optional<Category> getCategoryById(int id) {
        return categoryRepo.findById(id);
    }
}