package com.joeladjidan.gestiondestock.handlers;

import java.util.ArrayList;
import java.util.List;

import com.joeladjidan.gestiondestock.exception.ErrorCodes;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ErrorDto {

  private Integer httpCode;

  private ErrorCodes code;

  private String message;

  private List<String> errors = new ArrayList<>();

    public ErrorDto(Integer httpCode , String message) {
        this.httpCode = httpCode;
        this.message = message;
    }

    public ErrorDto(String message) {
        this.message = message;
    }
}
