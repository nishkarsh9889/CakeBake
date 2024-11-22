package com.cakebake.project.DTO;

import lombok.Data;

@Data
public class ProductDTO {
    private Long id;
    private String name;
    private double price;
    private String description;
    private double weight;
    private String imageName;
    private int categoryId;
}
