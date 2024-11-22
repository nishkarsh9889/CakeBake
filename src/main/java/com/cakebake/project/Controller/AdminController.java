package com.cakebake.project.Controller;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import com.cakebake.project.DTO.ProductDTO;
import com.cakebake.project.Model.Category;
import com.cakebake.project.Model.Product;
import com.cakebake.project.Services.CategoryServices;
import com.cakebake.project.Services.ProductServices;

@Controller
public class AdminController {
    public String uploadDir = "D:\\JAVA\\Spring boot\\project\\src\\main\\resources\\static\\productImages\\";

    @Autowired
    private CategoryServices categoryServices;

    @Autowired
    private ProductServices productServices;

    @GetMapping("/admin")
    public String adminHome() {
        return "adminHome";
    }

    @GetMapping("admin/categories")
    public String getCategories(Model model) {
        model.addAttribute("categories", categoryServices.getAllCategories());
        return "categories";
    }

    @GetMapping("/admin/categories/add")
    public String AddCat(Model model) {
        model.addAttribute("category", new Category());
        return "categoriesAdd";
    }

    @PostMapping("/admin/categories/add")
    public String postAddCat(@ModelAttribute("category") Category category) {
        categoryServices.addCategory(category);
        return "redirect:/admin/categories";
    }

    @GetMapping("/admin/categories/delete/{id}")
    public String deleteCatByID(@PathVariable int id) {
        categoryServices.removeCategoriesById(id);
        return "redirect:/admin/categories";
    }

    @GetMapping("/admin/categories/update/{id}")
    public String updateCat(@PathVariable int id, Model model) {
        Optional<Category> category = categoryServices.getCategoryById(id);
        if (category.isPresent()) {
            model.addAttribute("category", category.get());
            return "categoriesAdd";
        } else
            return "404";
    }

    // PRODUCT SECTION

    @GetMapping("/admin/products")
    public String getProducts(Model model) {
        model.addAttribute("products", productServices.getAllProducts());
        return "products";
    }

    @GetMapping("/admin/products/add")
    public String AddProduct(Model model) {
        model.addAttribute("productDTO", new ProductDTO());
        model.addAttribute("categories", categoryServices.getAllCategories());
        return "productsAdd";
    }

    @PostMapping("/admin/products/add")
    public String postAddProduct(@ModelAttribute("productDTO") ProductDTO productDTO,
            @RequestParam("productImage") MultipartFile file,
            @RequestParam("imgName") String imgName)
            throws IOException {

        Product product = new Product();
        product.setId(productDTO.getId());
        product.setName(productDTO.getName());
        product.setCategory(categoryServices.getCategoryById(productDTO.getCategoryId()).get());
        product.setDescription(productDTO.getDescription());
        product.setPrice(productDTO.getPrice());
        product.setWeight(productDTO.getWeight());

        if (!file.isEmpty()) {
            Files.createDirectories(Paths.get(uploadDir));

            String filePath = uploadDir + file.getOriginalFilename();
            File dest = new File(filePath);
            file.transferTo(dest);
        }
        product.setImageName(file.getOriginalFilename());

        productServices.addProduct(product);
        return "redirect:/admin/products";
    }

    @GetMapping("/admin/product/delete/{id}")
    public String deleteProductById(@PathVariable long id) {
        productServices.removeProductByID(id);
        return "redirect:/admin/products";
    }

    @GetMapping("/admin/product/update/{id}")
    public String updateProduct(@PathVariable long id, Model model) {
        Product product = productServices.getProductById(id).get();
        ProductDTO productDTO = new ProductDTO();

        productDTO.setId(product.getId());
        productDTO.setName(product.getName());
        productDTO.setCategoryId(product.getCategory().getId());
        productDTO.setPrice(product.getPrice());
        productDTO.setWeight(product.getWeight());
        productDTO.setDescription(product.getDescription());
        productDTO.setImageName(product.getImageName());

        model.addAttribute("categories", categoryServices.getAllCategories());
        model.addAttribute("productDTO", productDTO);

        return "productsAdd";
    }
}