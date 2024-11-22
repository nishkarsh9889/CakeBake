package com.cakebake.project.Services;

import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.cakebake.project.Model.Product;
import com.cakebake.project.Repository.ProductRepo;

@Service
public class ProductServices {

    @Autowired
    private ProductRepo productRepo;

    public List<Product> getAllProducts() {
        return productRepo.findAll();
    }

    public void addProduct(Product product) {
        productRepo.save(product);
    }

    public void removeProductByID(long id) {
        productRepo.deleteById(id);
    }

    public Optional<Product> getProductById(long id) {
        return productRepo.findById(id);
    }

    public List<Product> getAllProductsByCategoryid(int id) {
        return productRepo.findAllByCategory_Id(id);
    }
}
