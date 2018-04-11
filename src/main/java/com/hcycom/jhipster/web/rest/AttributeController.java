package com.hcycom.jhipster.web.rest;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import com.hcycom.jhipster.service.mapper.AttributeMapper;
import com.hcycom.jhipster.service.mapper.Attribute_valuesMapper;
import com.hcycom.jhipster.service.mapper.ResourceMapper;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

/**
 * 资源属性管理接口
 * 
 * @author Xi
 *
 */
@RestController
@RequestMapping("/api")
@Api(tags = { "资源属性管理" }, description = "资源属性管理接口")
public class AttributeController {

	@Autowired
	private AttributeMapper attributeMapper;

	@Autowired
	private Attribute_valuesMapper attribute_valuesMapper;
	
	@Autowired
	private  ResourceMapper resourceMapper;

	@RequestMapping(value = "/attribute", method = RequestMethod.POST)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/attribute--POST')")
	@ApiOperation(value = "创建资源属性", notes = "传入资源属性表参数，创建资源属性")
	public ResponseEntity<Map<String, Object>> attribute(@RequestBody Attribute attribute) {
		Map<String, Object> map = new HashMap<String, Object>();
		int i = attributeMapper.addAttribute(attribute);
		if (i == 0) {
			map.put("msg",
					"资源【" + attribute.getResource_name() + "】的【" + attribute.getAttribute_name() + "】属性创建失败！");
			map.put("error_code", 0);
		} else if (i > 0) {
			map.put("data", attribute);
			map.put("msg",
					"资源【" + attribute.getResource_name() + "】的【" + attribute.getAttribute_name() + "】属性创建失败！");
			map.put("error_code", 1);
		} else {
			map.put("msg", "服务器出问题了！");
			map.put("error_code", 2);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	@RequestMapping(value = "/attribute_update", method = RequestMethod.PUT)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/attribute_update--PUT')")
	@ApiOperation(value = "修改资源属性", notes = "传入资源属性表参数，根据资源属性key和资源名称修改资源属性")
	public ResponseEntity<Map<String, Object>> attribute_update(@RequestBody Attribute attribute) {
		Map<String, Object> map = new HashMap<String, Object>();
		int i = attributeMapper.updateAttribute(attribute);
		if (i == 0) {
			map.put("msg",
					"资源【" + attribute.getResource_name() + "】的【" + attribute.getAttribute_name() + "】属性修改失败！");
			map.put("error_code", 0);
		} else if (i > 0) {
			map.put("data", attribute);
			map.put("msg",
					"资源【" + attribute.getResource_name() + "】的【" + attribute.getAttribute_name() + "】属性修改成功！");
			map.put("error_code", 1);
		} else {
			map.put("msg", "服务器出问题了！");
			map.put("error_code", 2);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	@RequestMapping(value = "/attribute_delete", method = RequestMethod.DELETE)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/attribute_delete--DELETE')")
	@ApiOperation(value = "删除资源属性", notes = "传入资源属性表参数，根据资源属性key和资源名称删除资源属性")
	public ResponseEntity<Map<String, Object>> attribute_delete(@RequestBody Map<String, String> map) {
		Map<String, Object> re = new HashMap<String, Object>();
		for (String key : map.keySet()) {
			Attribute attribute = new Attribute();
			attribute.setResource_name(key);
			attribute.setAttribute_key(map.get(key) + "");
			if (map.get(key).equals("")) {
				String save_table=resourceMapper.findResoureByResource_name(attribute.getResource_name()).getSave_table();
				int i = attributeMapper.deleteAttributeByResource_nameLimit(attribute);
				if (i > 0) {
					List<String> list = attributeMapper.findAttributeByResource_nameNoLimit(attribute);
					String Listkey = "";
					for (String string : list) {
						Listkey += "\"" + string + "\",";
					}
					if (!Listkey.equals("")) {
						Listkey = Listkey.substring(0, Listkey.length() - 1);
					}
					attribute_valuesMapper.deleteAttribute_valuesByResource_nameNolimit(Listkey,attribute.getResource_name(),save_table);
				}
			} else {
				attribute=attributeMapper.findAttributeByResource_nameAndAttribute_key(attribute);
				if(attribute.getIs_delete()==0){
					attributeMapper.deleteAttributeByResource_nameAndAttribute_key(attribute);
					Attribute_values attribute_values=new Attribute_values();
					attribute_values.setAttribute_key(attribute.getAttribute_key());
					attribute_values.setResource_name(attribute.getResource_name());
					attribute_valuesMapper.deleteAttribute_valuesByResource_nameAndAttribute_key(attribute_values);
				}
			}
		}
		re.put("msg", "执行删除完成！");
		re.put("error_code", 1);
		return new ResponseEntity<Map<String, Object>>(re, HttpStatus.OK);
	}

	@RequestMapping(value = "/attribute_get", method = RequestMethod.GET)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/attribute_get--GET')")
	@ApiOperation(value = "获取资源属性", notes = "传入资源属性表参数，根据资源属性key和资源名称获取资源，若属性key为空返回所有指定资源名称的属性详情")
	public ResponseEntity<Map<String, Object>> attribute_get(
			@RequestParam(value = "attribute_key", required = true) String attribute_key,
			@RequestParam(value = "resource_name") String resource_name) {
		Map<String, Object> map = new HashMap<String, Object>();
		Attribute attribute = new Attribute();
		attribute.setAttribute_key(attribute_key);
		attribute.setResource_name(resource_name);
		if (attribute.getAttribute_key().equals("") || attribute.getAttribute_key() == null) {
			List<Attribute> list = attributeMapper.findAttributeByResource_name(attribute);
			map.put("data", list);
			map.put("msg", "资源【" + attribute.getResource_name() + "】的所有属性查询成功！");
			map.put("error_code", 0);

		} else {
			attribute = attributeMapper.findAttributeByResource_nameAndAttribute_key(attribute);
			map.put("data", attribute);
			map.put("msg",
					"资源【" + attribute.getResource_name() + "】的【" + attribute.getAttribute_key() + "】属性查询成功！");
			map.put("error_code", 0);
		}

		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	@RequestMapping(value = "/attribute_getAll", method = RequestMethod.GET)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/attribute_getAll--GET')")
	@ApiOperation(value = "获取资源属性", notes = "传入资源属性表参数，根据资源属性key和资源名称获取资源")
	public ResponseEntity<Map<String, Object>> attribute_getAll() {
		Map<String, Object> map = new HashMap<String, Object>();
		List<Attribute> list = attributeMapper.findAttributeAll();
		if (list.size() > 0) {
			map.put("data", list);
			map.put("msg", "所有资源属性获取成功！");
			map.put("error_code", 1);
		} else if (list.size() <= 0) {
			map.put("data", list);
			map.put("msg", "所有资源属性获取失败或资源属性为空！");
			map.put("error_code", 0);
		} else {
			map.put("msg", "服务器错误！");
			map.put("error_code", 2);
		}

		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

}
