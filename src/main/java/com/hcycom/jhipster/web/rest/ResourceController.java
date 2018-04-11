package com.hcycom.jhipster.web.rest;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.codahale.metrics.annotation.Timed;
import com.hcycom.jhipster.domain.Attribute;
import com.hcycom.jhipster.domain.Attribute_values;
import com.hcycom.jhipster.domain.Resource;
import com.hcycom.jhipster.service.mapper.AttributeMapper;
import com.hcycom.jhipster.service.mapper.Attribute_valuesMapper;
import com.hcycom.jhipster.service.mapper.ResourceMapper;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

/**
 * 资源管理接口
 * @author Xi
 *
 */
@RestController
@RequestMapping("/api")
@Api(tags = { "资源管理" }, description = "资源管理接口")
public class ResourceController {
	private final Logger log = LoggerFactory.getLogger(ResourceController.class);
	
	@Autowired
	private ResourceMapper resourceMapper;
	
	@Autowired
	private AttributeMapper attributeMapper;
	
	@Autowired
	private Attribute_valuesMapper attribute_valuesMapper;
	
	@RequestMapping(value = "/resource", method = RequestMethod.POST)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/resource--POST')")
	@ApiOperation(value = "创建资源", notes = "传入资源表参数，创建资源")
	public ResponseEntity<Map<String, Object>> resource(@RequestBody Resource resource){
		Map<String, Object> map = new HashMap<String, Object>();
		if(resource.getSave_table()==null){
			resource.setSave_table("attribute_values");
		}else if(resource.getSave_table().trim().equals("")){
			resource.setSave_table("attribute_values");
		}
		if(resourceMapper.findTable(resource)==null){
			resourceMapper.addResourceTable(resource);
		};
		int i=resourceMapper.addResource(resource);
		if(i==0){
			map.put("msg","资源【"+resource.getResource_name()+"】创建失败！");
			map.put("error_code", 0);
		}else if(i>0){
			map.put("data",resource);
			map.put("msg","资源【"+resource.getResource_name()+"】创建成功！");
			map.put("error_code", 1);
		}else {
			map.put("msg","服务器出问题了！");
			map.put("error_code", 2);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/resource_update", method = RequestMethod.PUT)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/resource_update--PUT')")
	@ApiOperation(value = "修改资源", notes = "传入资源表参数，根据资源名称修改资源")
	public ResponseEntity<Map<String, Object>> resource_update(@RequestBody Resource resource){
		Map<String, Object> map = new HashMap<String, Object>();
		int i=resourceMapper.updateResource(resource);
		if(i==0){
			map.put("msg","资源【"+resource.getResource_name()+"】修改失败！");
			map.put("error_code", 0);
		}else if(i>0){
			map.put("data",resource);
			map.put("msg","资源【"+resource.getResource_name()+"】修改成功！");
			map.put("error_code", 1);
		}else {
			map.put("msg","服务器出问题了！");
			map.put("error_code", 2);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/resource_delete", method = RequestMethod.DELETE)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/resource_delete--DELETE')")
	@ApiOperation(value = "删除资源", notes = "传入资源表参数，根据资源名称删除资源")
	public ResponseEntity<Map<String, Object>> resource_delete(@RequestBody Resource resource){
		Map<String, Object> map = new HashMap<String, Object>();
		resource=resourceMapper.findResoureByResource_name(resource.getResource_name());
		if(resource.getIs_delete()==1){
			map.put("msg","资源删除失败,该资源为不可删除资源！");
			map.put("error_code", 1);
			return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
		}
		List<String> otherTable=resourceMapper.findOtherTable(resource);
		if (otherTable.size()==1&&resource.getResource_name().equals(otherTable.get(0))) {
			resourceMapper.deleteResourceTable(resource);
		}else{
			Attribute_values attribute_values=new Attribute_values();
			attribute_values.setResource_name(resource.getResource_name());
			attribute_values.setSave_table(resource.getSave_table());
			attribute_valuesMapper.deleteAttribute_valuesByResource_name(attribute_values);
		}
		int i=resourceMapper.deleteResource(resource);
		if(i==0){
			map.put("msg","资源【"+resource.getResource_name()+"】删除失败！");
			map.put("error_code", 0);
		}else if(i>0){
			Attribute attribute=new Attribute();
			attribute.setResource_name(resource.getResource_name());
			attributeMapper.deleteAttributeByResource_nameNoLimit(attribute);
			map.put("msg","资源【"+resource.getResource_name()+"】删除成功！");
			map.put("error_code", 1);
		}else {
			map.put("msg","服务器出问题了！");
			map.put("error_code", 2);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/resource_deleteMore", method = RequestMethod.DELETE)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/resource_deleteMore--DELETE')")
	@ApiOperation(value = "批量删除资源", notes = "根据多个资源名称resource_names批量删除资源")
	public ResponseEntity<Map<String, Object>> resource_deleteMore(@RequestBody String[] resource_names){
		Map<String, Object> map = new HashMap<String, Object>();
		for (String string : resource_names) {
			Resource resource=new Resource();
			resource.setResource_name(string);
			resource=resourceMapper.findResoureByResource_name(resource.getResource_name());
			if(resource.getIs_delete()==1){
				map.put("msg","批量资源删除失败,【"+string+"】该资源为不可删除资源！");
				map.put("error_code", 0);
				return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
			}
			List<String> otherTable=resourceMapper.findOtherTable(resource);
			if (otherTable.size()==1&&resource.getResource_name().equals(otherTable.get(0))) {
				resourceMapper.deleteResourceTable(resource);
			}else{
				Attribute_values attribute_values=new Attribute_values();
				attribute_values.setResource_name(resource.getResource_name());
				attribute_values.setSave_table(resource.getSave_table());
				attribute_valuesMapper.deleteAttribute_valuesByResource_name(attribute_values);
			}
			resourceMapper.deleteResource(resource);
			Attribute attribute=new Attribute();
			attribute.setResource_name(resource.getResource_name());
			attributeMapper.deleteAttributeByResource_nameNoLimit(attribute);
		}
			map.put("msg","批量删除资源成功！");
			map.put("error_code", 1);
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/resource_get", method = RequestMethod.GET)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/resource_get--GET')")
	@ApiOperation(value = "获取资源", notes = "传入资源表参数，根据资源名称获取资源")
	public ResponseEntity<Map<String, Object>> resource_get(@RequestParam(value = "resource_name") String resource_name){
		Resource resource=new Resource();
		Map<String, Object> map = new HashMap<String, Object>();
		resource=resourceMapper.findResoureByResource_name(resource_name);
		if(resource!=null){
			map.put("data",resource);
			map.put("msg","资源【"+resource_name+"】获取成功！");
			map.put("error_code", 1);
		}else if(resource==null){
			map.put("data",resource);
			map.put("msg","资源获取失败或为空！");
			map.put("error_code", 0);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/resource_getAll", method = RequestMethod.GET)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/resource_getAll--GET')")
	@ApiOperation(value = "获取所有资源", notes = "获取所有资源")
	public ResponseEntity<Map<String, Object>> resource_getAll(){
		Map<String, Object> map = new HashMap<String, Object>();
		List<Resource> list=resourceMapper.findResoureAll();
		if(list.size()>0){
			map.put("data",list);
			map.put("msg","所有资源获取成功！");
			map.put("error_code", 1);
			log.info("resource："+map);
		}else if(list.size()<=0){
			map.put("data",list);
			map.put("msg","所有资源获取失败或者为空！");
			map.put("error_code", 0);
			log.info("resource："+map);
		}else {
			map.put("msg","服务器出问题了！");
			map.put("error_code", 2);
			log.info("resource："+map);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}
	
	
	
}
