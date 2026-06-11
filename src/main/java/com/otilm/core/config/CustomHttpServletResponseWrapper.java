package com.otilm.core.config;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class CustomHttpServletResponseWrapper extends HttpServletResponseWrapper {

    public List<Byte> rawData = new ArrayList<>();
    public HttpServletResponse response;
    private CachedBodyServletOutputStream servletStream;

    CustomHttpServletResponseWrapper(HttpServletResponse response) throws IOException {
        super(response);
        this.response = response;
        this.servletStream = new CachedBodyServletOutputStream(this);
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        return servletStream;
    }
    public PrintWriter getWriter() throws IOException {
        String encoding = getCharacterEncoding();
        if ( encoding != null ) {
            return new PrintWriter(new OutputStreamWriter(servletStream, encoding));
        } else {
            return new PrintWriter(new OutputStreamWriter(servletStream));
        }
    }

}
