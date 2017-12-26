package com.hcycom.jhipster.service.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import com.hcycom.jhipster.domain.Group;

@Mapper
public interface GroupMapper {

	/**
	 * 添加群组信息
	 * @param role
	 * @return
	 */
	@Insert(value="INSERT INTO `group` (uuid,group_name,group_desc,"
			+ "group_super,group_type,group_status) VALUES " 
	 + "(#{group.uuid},#{group.group_name},#{group.group_desc},"
	 + "#{group.group_super},#{group.group_type},#{group.group_status})")
	public int addGroup(@Param("group") Group group);

	/**
	 * 修改群组信息
	 * @param role
	 * @return
	 */
	@Update("update `group`  set group_name = #{group.group_name},group_desc = #{group.group_desc},"
			+ "group_super = #{group.group_super},group_type = #{group.group_type},"
			+ "group_status = #{group.group_status} "
			+ "where uuid=#{group.uuid}")
	public int updateGroup(@Param("group") Group group);

	/**
	 * 根据uuid删除群组信息
	 * @param role
	 * @return
	 */
	@Delete("delete from `group`  where uuid=#{group.uuid}")
	public int deleteGroup(@Param("group") Group group);
	

	/**
	 * 根据uuid查询群组信息
	 * @param roleid
	 * @return
	 */
	@Select("select * from `group`  where uuid=#{groupid}")
	public Group getGroupById(@Param("groupid") String groupid);
	


	/**
	 * 查询所有群组
	 * @return
	 */
	@Select("select * from `group` ")
	public List<Group> getAllGroup();

}
