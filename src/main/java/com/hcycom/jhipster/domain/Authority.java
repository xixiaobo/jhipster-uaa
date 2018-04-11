package com.hcycom.jhipster.domain;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Column;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.io.Serializable;

@Entity
@Table(name = "jhi_authority")
public class Authority implements Serializable {

	 private static final long serialVersionUID = 1L;

	    @NotNull
	    @Size(max = 50)
	    @Id
	    @Column(length = 50)
	    private String name;

	    public String getName() {
	        return name;
	    }

	    public void setName(String name) {
	        this.name = name;
	    }

	    @Override
	    public boolean equals(Object o) {
	        if (this == o) {
	            return true;
	        }
	        if (o == null || getClass() != o.getClass()) {
	            return false;
	        }

	        Authority authority = (Authority) o;

	        return !(name != null ? !name.equals(authority.name) : authority.name != null);
	    }

	    @Override
	    public int hashCode() {
	        return name != null ? name.hashCode() : 0;
	    }

	    @Override
	    public String toString() {
	        return "Authority{" +
	            "name='" + name + '\'' +
	            "}";
	    }
	    
	private String uuid;
	private String authority_name;
	private String authority_type;
	private String foreign_uuid;
	private String authority_url;
	private int authority_status;
	
	public String getUuid() {
		return uuid;
	}
	public void setUuid(String uuid) {
		this.uuid = uuid;
	}
	public String getAuthority_name() {
		return authority_name;
	}
	public void setAuthority_name(String authority_name) {
		this.authority_name = authority_name;
	}
	public String getAuthority_type() {
		return authority_type;
	}
	public void setAuthority_type(String authority_type) {
		this.authority_type = authority_type;
	}
	
	public String getForeign_uuid() {
		return foreign_uuid;
	}
	public void setForeign_uuid(String foreign_uuid) {
		this.foreign_uuid = foreign_uuid;
	}
	public String getAuthority_url() {
		return authority_url;
	}
	public void setAuthority_url(String authority_url) {
		this.authority_url = authority_url;
	}
	public int getAuthority_status() {
		return authority_status;
	}
	public void setAuthority_status(int authority_status) {
		this.authority_status = authority_status;
	}
	
	
}
