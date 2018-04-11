package com.hcycom.jhipster.web.rest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.codahale.metrics.annotation.Timed;
import com.hcycom.jhipster.domain.Attribute_values;
import com.hcycom.jhipster.service.mapper.Attribute_valuesMapper;
import com.hcycom.jhipster.service.mapper.ResourceMapper;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;

/**
 * 资源属性值管理接口
 * 
 * @author Xi
 *
 */
@RestController
@RequestMapping("/api")
@Api(tags = { "资源属性值管理" }, description = "资源属性值管理接口")
public class Attribute_valuesController {

	@Autowired
	private Attribute_valuesMapper attribute_valuesMapper;
	@Autowired
	private ResourceMapper resourceMapper;

	@RequestMapping(value = "/getNewAttributevaluesUUID", method = RequestMethod.GET)
	@Timed
	@ApiOperation(value = "生成资源数据记录UUID接口", notes = "生成资源数据记录UUID，无权限控制")
	public ResponseEntity<Map<String, Object>> getNewAttributevaluesUUID() {
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("uuid", UUID.randomUUID().toString().replaceAll("-", ""));
		map.put("msg", "UUID生成成功");
		map.put("error_code", 1);
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	@RequestMapping(value = "/attributevalues", method = RequestMethod.POST)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/attributevalues--POST')")
	@ApiOperation(value = "新增单条资源数据记录接口", notes = "传入单条资源属性值表参数，新增资源数据记录需要传递UUID")
	public ResponseEntity<Map<String, Object>> attributevalues(@RequestBody Attribute_values attribute_values) {
		Map<String, Object> map = new HashMap<String, Object>();
		if (attribute_values.getResource_name().equals("user")) {
			map.put("msg", "不可以手动操作用户表请到用户管理处添加！");
			map.put("error_code", 0);
			return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
		}
		attribute_values.setSave_table(
				resourceMapper.findResoureByResource_name(attribute_values.getResource_name()).getSave_table());
		int i = attribute_valuesMapper.addAttribute_values(attribute_values);
		if (i == 0) {
			map.put("msg", "资源【" + attribute_values.getResource_name() + "】录入一条数据失败！");
			map.put("error_code", 0);
		} else if (i > 0) {
			map.put("data", attribute_values);
			map.put("msg", "资源【" + attribute_values.getResource_name() + "】成功录入一条数据！");
			map.put("error_code", 1);
		} else {
			map.put("msg", "服务器出问题了！");
			map.put("error_code", 2);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	@RequestMapping(value = "/attributevaluesMore", method = RequestMethod.POST)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/attributevaluesMore--POST')")
	@ApiOperation(value = "新增多条资源数据记录接口", notes = "传入资源名称、uuid和多条资源属性值表参数，新增资源数据记录需要传递UUID")
	public ResponseEntity<Map<String, Object>> attributevaluesMore(@RequestBody Map<String, Object> map) {
		Map<String, Object> map2 = new HashMap<String, Object>();
		if (map.get("resource_name").equals("user")) {
			map2.put("msg", "不可以手动操作用户表请到用户管理处添加！");
			map2.put("error_code", 0);
			return new ResponseEntity<Map<String, Object>>(map2, HttpStatus.OK);
		}
		String resource_name = map.get("resource_name") + "";
		String save_table = resourceMapper.findResoureByResource_name(resource_name).getSave_table();
		String uuid = map.get("uuid") + "";
		map.remove("resource_name");
		for (String key : map.keySet()) {
			Attribute_values attribute_values = new Attribute_values();
			attribute_values.setUuid(uuid);
			attribute_values.setSave_table(save_table);
			attribute_values.setResource_name(resource_name);
			attribute_values.setAttribute_key(key);
			attribute_values.setValue(map.get(key) + "");
			attribute_valuesMapper.addAttribute_values(attribute_values);
		}
		map2.put("msg", "资源成功录入数据！");
		map2.put("error_code", 1);
		return new ResponseEntity<Map<String, Object>>(map2, HttpStatus.OK);
	}

	@RequestMapping(value = "/attributevalues_update", method = RequestMethod.PUT)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/attributevalues_update--PUT')")
	@ApiOperation(value = "修改资源数据记录", notes = "传入资源数据记录参数，根据资源数据记录的uuid、资源数据记录属性key和资源名称修改资源数据记录")
	public ResponseEntity<Map<String, Object>> attributevalues_update(@RequestBody Map<String, Object> map) {
		Map<String, Object> map2 = new HashMap<String, Object>();
		if (map.get("resource_name").equals("user")) {
			map2.put("msg", "不可以手动操作用户表请到用户管理处添加！");
			map2.put("error_code", 0);
			return new ResponseEntity<Map<String, Object>>(map2, HttpStatus.OK);
		}
		String resource_name = map.get("resource_name") + "";
		String save_table = resourceMapper.findResoureByResource_name(resource_name).getSave_table();
		String uuid = map.get("uuid") + "";
		map.remove("resource_name");
		map.remove("uuid");
		for (String key : map.keySet()) {
			Attribute_values attribute_values = new Attribute_values();
			attribute_values.setUuid(uuid);
			attribute_values.setSave_table(save_table);
			attribute_values.setResource_name(resource_name);
			attribute_values.setAttribute_key(key);
			attribute_values.setValue(map.get(key) + "");
			attribute_valuesMapper.updateAttribute_values(attribute_values);
		}
		map2.put("msg", "记录修改成功");
		map2.put("error_code", 1);
		return new ResponseEntity<Map<String, Object>>(map2, HttpStatus.OK);
	}

	@RequestMapping(value = "/attributevalues_deleteByUUID", method = RequestMethod.DELETE)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/attributevalues_deleteByUUID--DELETE')")
	@ApiOperation(value = "根据UUID删除资源数据记录", notes = "传入资源数据记录参数，根据资源数据记录的uuid和资源名称删除资源数据记录")
	public ResponseEntity<Map<String, Object>> attributevalues_deleteByUUID(
			@RequestBody Attribute_values attribute_values) {
		Map<String, Object> map = new HashMap<String, Object>();
		if (attribute_values.getResource_name().equals("user")) {
			map.put("msg", "不可以手动操作用户表请到用户管理处添加！");
			map.put("error_code", 0);
			return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
		}
		attribute_values.setSave_table(
				resourceMapper.findResoureByResource_name(attribute_values.getResource_name()).getSave_table());
		int i = attribute_valuesMapper.deleteAttribute_valuesByResource_nameAndUuid(attribute_values);
		if (i == 0) {
			map.put("msg", "资源记录删除失败");
			map.put("error_code", 0);
		} else if (i > 0) {
			map.put("data", attribute_values);
			map.put("msg", "资源记录删除成功");
			map.put("error_code", 1);
		} else {
			map.put("msg", "服务器出问题了！");
			map.put("error_code", 2);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	@RequestMapping(value = "/attributevalues_deleteByUUIDMore", method = RequestMethod.DELETE)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/attributevalues_deleteByUUIDMore--DELETE')")
	@ApiOperation(value = "批量删除资源数据记录", notes = "根据UUID以及资源名称集合批量删除资源数据记录")
	public ResponseEntity<Map<String, Object>> attributevalues_deleteByUUIDMore(
			@RequestBody List<Attribute_values> attribute_valuesMore) {
		Map<String, Object> re = new HashMap<String, Object>();
		for (Attribute_values attribute_values : attribute_valuesMore) {
			if (attribute_values.getResource_name().equals("user")) {
				re.put("msg", "不可以手动操作用户表请到用户管理处添加！");
				re.put("error_code", 0);
				return new ResponseEntity<Map<String, Object>>(re, HttpStatus.OK);
			}
			attribute_values.setSave_table(
					resourceMapper.findResoureByResource_name(attribute_values.getResource_name()).getSave_table());
			attribute_valuesMapper.deleteAttribute_valuesByResource_nameAndUuid(attribute_values);
		}
		re.put("msg", "资源记录删除成功");
		re.put("error_code", 1);
		return new ResponseEntity<Map<String, Object>>(re, HttpStatus.OK);
	}

	@RequestMapping(value = "/attributevalues_deleteByOnly", method = RequestMethod.DELETE)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/attributevalues_deleteByOnly--DELETE')")
	@ApiOperation(value = "根据UUID以及属性key删除资源数据记录", notes = "传入资源数据记录参数，根据资源数据记录的uuid、属性key和资源名称删除资源数据记录")
	public ResponseEntity<Map<String, Object>> attributevalues_deleteByOnly(
			@RequestBody Attribute_values attribute_values) {
		Map<String, Object> map = new HashMap<String, Object>();
		if (attribute_values.getResource_name().equals("user")) {
			map.put("msg", "不可以手动操作用户表请到用户管理处添加！");
			map.put("error_code", 0);
			return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
		}
		attribute_values.setSave_table(
				resourceMapper.findResoureByResource_name(attribute_values.getResource_name()).getSave_table());
		int i = attribute_valuesMapper.deleteAttribute_valuesByOnly(attribute_values);
		if (i == 0) {
			map.put("msg", "资源记录删除失败");
			map.put("error_code", 0);
		} else if (i > 0) {
			map.put("data", attribute_values);
			map.put("msg", "资源记录删除成功");
			map.put("error_code", 1);
		} else {
			map.put("msg", "服务器出问题了！");
			map.put("error_code", 2);
		}
		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	@RequestMapping(value = "/attributevalues_get", method = RequestMethod.GET)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/attributevalues_get--GET')")
	@ApiOperation(value = "获取资源数据记录", notes = "传入资源数据记录参数，根据资源数据记录的uuid和资源名称获取资源数据记录,如果不传uuid则根据资源名称获取资源记录")
	public ResponseEntity<Map<String, Object>> attributevalues_get(
			@RequestParam(value = "uuid", required = false) String uuid,
			@RequestParam(value = "resource_name") String resource_name) {
		Map<String, Object> map = new HashMap<String, Object>();
		Attribute_values attribute_values = new Attribute_values();
		attribute_values.setUuid(uuid);
		attribute_values.setResource_name(resource_name);
		attribute_values.setSave_table(
				resourceMapper.findResoureByResource_name(attribute_values.getResource_name()).getSave_table());
		if (attribute_values.getUuid() == null) {
			List<Attribute_values> list = attribute_valuesMapper.findAttribute_valuesByResource_name(attribute_values);
			List<String> liststring = new ArrayList<String>();

			for (Attribute_values value : list) {
				liststring.add(value.getUuid());
			}
			Set<String> set = new HashSet<String>();
			List<String> newList = new ArrayList<String>();
			for (String cd : liststring) {
				if (set.add(cd)) {
					newList.add(cd);
				}
			}
			List<Map<String, String>> valuesmap = new ArrayList<Map<String, String>>();
			for (String string : newList) {
				Map<String, String> valuemap = new HashMap<String, String>();
				for (Attribute_values values2 : list) {
					if (values2.getUuid().equals(string)) {
						valuemap.put(values2.getAttribute_key(), values2.getValue());
					}
				}
				valuesmap.add(valuemap);
			}
			map.put("data", valuesmap);
			map.put("msg", "资源【" + attribute_values.getResource_name() + "】的所有属性查询成功！");
			map.put("error_code", 1);

		} else {
			List<Attribute_values> list = attribute_valuesMapper
					.findAttribute_valuesByResource_nameANDUuid(attribute_values);
			List<String> liststring = new ArrayList<String>();

			for (Attribute_values value : list) {
				liststring.add(value.getUuid());
			}
			Set<String> set = new HashSet<String>();
			List<String> newList = new ArrayList<String>();
			for (String cd : liststring) {
				if (set.add(cd)) {
					newList.add(cd);
				}
			}
			List<Map<String, String>> valuesmap = new ArrayList<Map<String, String>>();
			for (String string : newList) {
				Map<String, String> valuemap = new HashMap<String, String>();
				for (Attribute_values values2 : list) {
					if (values2.getUuid().equals(string)) {
						valuemap.put(values2.getAttribute_key(), values2.getValue());
					}
				}
				valuesmap.add(valuemap);
			}
			map.put("data", valuesmap);
			map.put("msg",
					"资源【" + attribute_values.getResource_name() + "】的【" + attribute_values.getUuid() + "】属性查询成功！");
			map.put("error_code", 1);
		}

		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	@RequestMapping(value = "/attributevalues_getByKey", method = RequestMethod.GET)
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/attributevalues_getByKey--GET')")
	@ApiOperation(value = "获取资源数据记录", notes = "传入资源数据记录参数，根据资源数据记录的uuid和资源名称获取资源数据记录,如果不传uuid则根据资源名称获取资源记录")
	public ResponseEntity<Map<String, Object>> attributevalues_getByKey(@RequestParam(value = "key") String key,
			@RequestParam(value = "value") String value, @RequestParam(value = "resource_name") String resource_name) {
		Map<String, Object> map = new HashMap<String, Object>();
		Attribute_values attribute_values = new Attribute_values();
		attribute_values.setAttribute_key(key);
		attribute_values.setValue(value);
		attribute_values.setResource_name(resource_name);
		attribute_values.setSave_table(
				resourceMapper.findResoureByResource_name(attribute_values.getResource_name()).getSave_table());
		List<Attribute_values> list = attribute_valuesMapper
				.findAttribute_valuesByResource_nameANDKeyAndValue(attribute_values);
		List<String> liststring = new ArrayList<String>();

		for (Attribute_values values : list) {
			liststring.add(values.getUuid());
		}
		Set<String> set = new HashSet<String>();
		List<String> newList = new ArrayList<String>();
		for (String cd : liststring) {
			if (set.add(cd)) {
				newList.add(cd);
			}
		}
		List<Map<String, String>> valuesmap = new ArrayList<Map<String, String>>();
		for (String string : newList) {
			Map<String, String> valuemap = new HashMap<String, String>();
			for (Attribute_values values2 : list) {
				if (values2.getUuid().equals(string)) {
					valuemap.put(values2.getAttribute_key(), values2.getValue());
				}
			}
			valuesmap.add(valuemap);
		}
		map.put("data", valuesmap);
		map.put("msg", "资源查询成功！");
		map.put("error_code", 1);

		return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	}

	/**
	 * 获取所有用户表属性
	 * 
	 * @return
	 */
	@PostMapping("/getattribute_valuesByLike")
	@Timed
	@PreAuthorize("@InterfacePermissions.hasPermission(authentication, 'usermodule/api/getattribute_valuesByLike--POST')")
	@ApiOperation(value = "获取筛选资源属性值", notes = "获取筛选后资源属性值,map:{\"resource_name\":\"你所要查询的资源\",\"你所要查询的字段\":\"你所要查询的值\"},可以查询多个字段", httpMethod = "POST")
	public ResponseEntity<Map<String, Object>> getusersByLike(
			@ApiParam(name = "筛选资源属性值", value = "参数模型：{\"resource_name\":\"你所要查询的资源\",\"你所要查询的字段\":\"你所要查询的值\"}") @RequestBody Map<String, Object> map) {
		List<String> uuids = new ArrayList<String>();
		String resource_name = "";
		if (map.containsKey("resource_name")) {
			resource_name = map.get("resource_name") + "";
			map.remove("resource_name");
		} else {
			Map<String, Object> map3 = new HashMap<String, Object>();
			map3.put("msg", "资源名称不能为空！");
			map3.put("error_code", 0);
			return new ResponseEntity<Map<String, Object>>(map3, HttpStatus.OK);
		}
		String save_table=resourceMapper.findResoureByResource_name(resource_name).getSave_table();
		for (String key : map.keySet()) {
			Attribute_values attribute_values = new Attribute_values();
			attribute_values.setResource_name(resource_name);
			attribute_values.setAttribute_key(key);
			String value = map.get(key) + "";
			String sql = "\"%" + value.replace(" ", "") + "%\"";
			attribute_values.setSave_table(save_table);
			List<String> list2 = attribute_valuesMapper.findAttribute_valuesByKeyAndValue(attribute_values, sql);
			list2.removeAll(uuids);
			uuids.addAll(list2);
		}
		String ListID = "\"\",";
		for (String string : uuids) {
			ListID += "\"" + string + "\",";
		}
		ListID = ListID.substring(0, ListID.length() - 1);
		Attribute_values attribute_values = new Attribute_values();
		attribute_values.setResource_name(resource_name);
		attribute_values.setSave_table(save_table);
		List<Attribute_values> list = attribute_valuesMapper.findAttribute_valuesByListID(ListID, attribute_values);
		List<String> liststring = new ArrayList<String>();

		for (Attribute_values value : list) {
			liststring.add(value.getUuid());
		}
		Set<String> set = new HashSet<String>();
		List<String> newList = new ArrayList<String>();
		for (String cd : liststring) {
			if (set.add(cd)) {
				newList.add(cd);
			}
		}
		List<Map<String, String>> valuesmap = new ArrayList<Map<String, String>>();
		for (String string : newList) {
			Map<String, String> valuemap = new HashMap<String, String>();
			for (Attribute_values values2 : list) {
				if (values2.getUuid().equals(string)) {
					valuemap.put(values2.getAttribute_key(), values2.getValue());
				}
			}
			valuesmap.add(valuemap);
		}
		Map<String, Object> map3 = new HashMap<String, Object>();
		if (list.size() > 0) {
			map.put("data", valuesmap);
			map3.put("LikeMap", map);
			map3.put("msg", "成功获取筛选后" + resource_name + "资源属性值！");
			map3.put("error_code", 1);
		} else if (list.size() == 0) {
			map3.put("LikeMap", map);
			map3.put("msg", "获取筛选后" + resource_name + "资源属性值失败或获取筛选后" + resource_name + "资源属性值为空！");
			map3.put("error_code", 0);
		} else {
			map3.put("msg", "服务器出问题了！");
			map3.put("error_code", 2);
		}

		return new ResponseEntity<Map<String, Object>>(map3, HttpStatus.OK);
	}

	// @RequestMapping(value = "/attributevalues_getAll", method =
	// RequestMethod.GET)
	// @Timed
	// @PreAuthorize("@InterfacePermissions.hasPermission(authentication,
	// 'usermodule/api/attributevalues_getAll--GET')")
	// @ApiOperation(value = "获取资源数据记录", notes =
	// "传入资源数据记录参数，根据资源数据记录的uuid和资源名称获取资源数据记录,如果不传uuid则根据资源名称获取资源记录")
	// public ResponseEntity<Map<String, Object>> attributevalues_getAll() {
	// Map<String, Object> map = new HashMap<String, Object>();
	// List<Attribute_values> list =
	// attribute_valuesMapper.findAttribute_valuesAll();
	// if (list.size() > 0) {
	// map.put("data", list);
	// map.put("msg", "查询所有属性成功！");
	// map.put("error_code", 1);
	// } else if (list.size() <= 0) {
	// map.put("msg", "查询所有属性失败或查询结果为空！");
	// map.put("error_code", 0);
	// } else {
	// map.put("msg", "服务器错误");
	// map.put("error_code", 2);
	// }
	//
	// return new ResponseEntity<Map<String, Object>>(map, HttpStatus.OK);
	// }

}
