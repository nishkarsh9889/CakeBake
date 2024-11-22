package com.cakebake.project.Controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cakebake.project.Global.GlobalData;
import com.cakebake.project.Services.CategoryServices;
import com.cakebake.project.Services.ProductServices;

@Controller
public class HomeController {
    @Autowired
    private CategoryServices categoryServices;
    @Autowired
    private ProductServices productServices;

    @GetMapping({ "/", "/home" })
    public String home() {
        return "index";
    }

    @GetMapping("/ok")
    @ResponseBody
    public String healthCheck() {
        return "OK";
    }

    @GetMapping("/shop")
    public String shop(Model model) {
        model.addAttribute("categories", categoryServices.getAllCategories());
        model.addAttribute("products", productServices.getAllProducts());
        model.addAttribute("cartCount", GlobalData.cart.size());
        return "shop";
    }

    @GetMapping("/shop/category/{id}")
    public String shopByCategory(Model model, @PathVariable int id) {
        model.addAttribute("categories", categoryServices.getAllCategories());
        model.addAttribute("products", productServices.getAllProductsByCategoryid(id));
        model.addAttribute("cartCount", GlobalData.cart.size());
        return "shop";
    }

    @GetMapping("/shop/viewproduct/{id}")
    public String viewProduct(Model model, @PathVariable int id) {
        model.addAttribute("product", productServices.getProductById(id).get());
        model.addAttribute("cartCount", GlobalData.cart.size());
        return "viewProduct";
    }
}