package com.cakebake.project.Global;

import java.util.ArrayList;
import java.util.List;

import com.cakebake.project.Model.Product;

public class GlobalData {
    public static List<Product> cart;
    static {
        cart = new ArrayList<>();
    }
}
