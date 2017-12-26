package com.hcycom.jhipster.web.rest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import com.codahale.metrics.annotation.Timed;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

@RestController
@RequestMapping("/api")
@Api(tags = { "接口路径管理" })
public class UrlMapping {
	private final Logger log = LoggerFactory.getLogger(UrlMapping.class);
	
	@Value("${spring.application.name}")
    String applicationName;
	
	@RequestMapping(value = "/getUrlMapping", method = RequestMethod.GET)
	@Timed
	@ApiOperation(value = "获取所有接口", notes = "获取所有应用接口", httpMethod = "GET")
	public ResponseEntity< List<Map<String, String>>>  getUrlMapping(HttpServletRequest request) {  
        WebApplicationContext wc = getWebApplicationContext(request.getSession().getServletContext());  
        RequestMappingHandlerMapping rmhp = wc.getBean(RequestMappingHandlerMapping.class);  
        Map<RequestMappingInfo, HandlerMethod> map = rmhp.getHandlerMethods();
       List<Map<String, String>> list=new ArrayList<Map<String, String>>();
        
        for (Iterator<RequestMappingInfo> iterator = map.keySet().iterator(); iterator    
                .hasNext();) {    
            RequestMappingInfo info = iterator.next();  
            String regEx  = "/api/[^\\s]*";
            String a=info.getPatternsCondition()+"";
            String url = a.replaceAll("[\\[\\]]", ""); 
            String b=info.getMethodsCondition()+"";
            String Methods = b.replaceAll("[\\[\\]]", "");  
            Pattern pattern = Pattern.compile(regEx);
            Matcher matcher = pattern.matcher(url);
            System.out.println("获取项目名="+applicationName);  
            if(matcher.matches()){
            	 Map<String, String> lMap=new HashMap<String,String>();
                 lMap.put("Methods", Methods);
                 lMap.put("url",applicationName+url);
                 list.add(lMap);
            }
        }  
        return new ResponseEntity< List<Map<String, String>>>(list, HttpStatus.OK);
    }

	
	private WebApplicationContext getWebApplicationContext(ServletContext servletContext) {
		// TODO Auto-generated method stub
		return WebApplicationContextUtils.getRequiredWebApplicationContext(servletContext);  
	}  
}
