/*  
 * ====================================================================  
 *  
 * The Apache Software License, Version 1.1  
 *  
 * Copyright (c) 1999 The Apache Software Foundation.  All rights  
 * reserved.  
 *  
 * Redistribution and use in source and binary forms, with or without  
 * modification, are permitted provided that the following conditions  
 * are met:  
 *  
 * 1. Redistributions of source code must retain the above copyright  
 *    notice, this list of conditions and the following disclaimer.  
 *  
 * 2. Redistributions in binary form must reproduce the above copyright  
 *    notice, this list of conditions and the following disclaimer in  
 *    the documentation and/or other materials provided with the  
 *    distribution.  
 *  
 * 3. The end-user documentation included with the redistribution, if  
 *    any, must include the following acknowlegement:  
 *       "This product includes software developed by the  
 *        Apache Software Foundation (http://www.apache.org/)."  
 *    Alternately, this acknowlegement may appear in the software itself,  
 *    if and wherever such third-party acknowlegements normally appear.  
 *  
 * 4. The names "The Jakarta Project", "Tomcat", and "Apache Software  
 *    Foundation" must not be used to endorse or promote products derived  
 *    from this software without prior written permission. For written  
 *    permission, please contact apache@apache.org.  
 *  
 * 5. Products derived from this software may not be called "Apache"  
 *    nor may "Apache" appear in their names without prior written  
 *    permission of the Apache Group.  
 *  
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED  
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES  
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE  
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR  
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,  
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT  
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF  
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND  
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,  
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT  
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF  
 * SUCH DAMAGE.  
 * ====================================================================  
 *  
 * This software consists of voluntary contributions made by many  
 * individuals on behalf of the Apache Software Foundation.  For more  
 * information on the Apache Software Foundation, please see  
 * <http://www.apache.org/>.  
 *  
 * Portions of this software are based upon public domain software  
 * originally written at the National Center for Supercomputing  
 * Applications, University of Illinois, Urbana-Champaign.  
 *  
 */   
package  gov.nist.security.rbac;   
   
import  java.io.*;   
import  java.util.*;   
   
/**  
 * A role base class that provides generic implemenation with no internal data set.  
 */   
public class AbstractGroup implements IGroup, Serializable {   
  /** Returns true iff this role is authorized with the specified permission. */   
  public boolean isAuthorized (IPermission perm) {   
    if (perm == null   
    ||  perm == IPermission.NO_PERMISSION   
    ||  perm.equals(IPermission.NO_PERMISSION)) {   
        return true;   
    }   
    return new Permission(getPermissions()).ge(perm);   
  }   
  /** Returns true iff this role is authorized with the specified permissions. */   
  public boolean isAuthorized (IPermission[] perm) {   
    if (perm == null) {   
        return true;   
    }   
    return new Permission(getPermissions()).ge(new Permission(perm));   
  }   
  /** Always returns zero. */   
  public int getMaxMembers () {   
    return  0;   
  }   
  /** Always returns a null set of user. */   
  public IRbacUser[] getAssignedUsers () {   
    return  IRbacUser.ZERO_USER;   
  }   
  /** Always returns a null set of permission. */   
  public IPermission[] getPermissions () {   
    return  IPermission.ZERO_PERMISSION;   
  }   
  /** Always returns a non-modifiable empty set of attributes. */   
  public Map getRoleAttributes () {   
    return  Collections.unmodifiableMap(new HashMap());   
  }   
  /** Two roles are equal if they have the same set of attributes and permissions. */   
  public boolean equals (Object o) {   
    if (o == null || !(o instanceof IRole)) {   
      return  false;   
    }   
    if (o == this) {   
      return true;   
    }   
    IRole r = (IRole)o;   
    Map attr = getRoleAttributes();   
    IPermission[] p = getPermissions();   
    Map to_attr = r.getRoleAttributes();   
    IPermission[] to_p = r.getPermissions();   
    if (!attr.equals(to_attr))   
      return  false;   
    if (p.length != to_p.length)   
      return  false;   
  outter:   
    for (int i = 0; i < p.length; i++) {   
      IPermission pi = p[i];   
   
      for (int j = 0; j < to_p.length; j++) {   
        IPermission pj = to_p[j];   
   
        if (pi.equals(pj)) {   
          continue outter;   
        }   
      }   
      return false;   
    }   
    return  true;   
  }   
   
  public int hashCode () {   
    int hash = getRoleAttributes().hashCode();   
    IPermission[] p = getPermissions();   
    if (p != null) {   
      for (int i=0; i < p.length; i++) {   
        hash ^= p[i].hashCode();   
      }   
    }   
    return hash;   
  }   
  /**  
   * Returns true iff the access privilege this role is  
   * greater than or equal to that of the given role.  
   */   
  public boolean ge(IRole r) {   
    if (r == null || r == this) {   
      return true;   
    }   
    IPermission[] p = getPermissions();   
    IPermission[] to_p = r.getPermissions();   
  outter:   
    for (int i = 0; i < to_p.length; i++) {   
      IPermission pi = to_p[i];   
   
      for (int j = 0; j < p.length; j++) {   
        IPermission pj = p[j];   
   
        if (pj.ge(pi)) {   
          continue outter;   
        }   
      }   
      return false;   
    }   
    return  true;   
  }   
  public String toString() {   
    StringBuffer sb = new StringBuffer();   
    Map map = getRoleAttributes();   
   
    for (Iterator itr=map.entrySet().iterator(); itr.hasNext();) {   
      Map.Entry entry = (Map.Entry)itr.next();   
      sb.append("\n");   
      sb.append(entry.getKey().toString());   
      sb.append("=");   
      sb.append(entry.getValue().toString());   
    }   
    IPermission[] p = getPermissions();   
    for (int i=0; i < p.length; i++) {   
      sb.append("\n");   
      sb.append(p[i].toString());   
    }   
    return sb.toString();   
  }   
  /** Always returns false. */   
  public boolean roleAdded(IRbacUser user) throws RbacSecurityViolation {   
    return false;   
  }   
  /** Always returns false. */   
  public boolean roleDropped(IRbacUser user) {   
    return false;   
  }   
  /** Always returns false. */   
  public boolean grantPermission(IPermission perm) {   
    return false;   
  }   
  /** Always returns false. */   
  public boolean revokePermission(IPermission perm) {   
    return false;   
  }   
}   