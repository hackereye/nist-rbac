   
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
package gov.nist.security.rbac;   
   
import java.io.*;   
import java.util.*;   
/**  
 * A RBAC session base class that provides generic implemenation with no internal data set.  
 */   
public class AbstractRbacSession implements IRbacSession, Serializable {   
  /** Returns true iff this session is authorized with the specified permission. */   
/*  
  public boolean isAuthorized(IPermission perm) {  
    if (perm == null  
    ||  perm == IPermission.NO_PERMISSION  
    ||  perm.equals(IPermission.NO_PERMISSION))  
    {  
      return true;  
    }  
    IRole[] role = getActiveRoles();  
    for (int i=0; i < role.length; i++) {  
      if (role[i].isAuthorized(perm)) {  
        return true;  
      }  
    }  
    return false;  
  }  
*/   
  public boolean isAuthorized(IPermission perm) {   
    if (perm == null   
    ||  perm == IPermission.NO_PERMISSION   
    ||  perm.equals(IPermission.NO_PERMISSION))   
    {   
      return true;   
    }   
    Set set = new HashSet();   
    IRole[] r = getActiveRoles();   
    for (int i=0; i < r.length; i++) {   
      set.add(new Permission(r[i].getPermissions()));   
    }   
    IPermission p = new Permission((IPermission[])set.toArray(IPermission.ZERO_PERMISSION));   
    return p.ge(perm);   
  }   
  /** Returns true iff this session is authorized with the specified permissions. */   
  public boolean isAuthorized(IPermission[] perm) {   
    if (perm == null) {   
        return true;   
    }   
    return isAuthorized(new Permission(perm));   
  }   
  /** Returns true iff this session is authorized with the permissions of the specified role. */   
  public boolean isAuthorized(IRole role) {   
    if (role == null) {   
      return true;   
    }   
    return isAuthorized(role.getPermissions());   
  }   
  /** A no-op that always returns false. */   
  public boolean addActiveRole(IRole r) {   
    return false;   
  }   
  /** A no-op that always returns false. */   
  public boolean dropActiveRole(IRole r) {   
    return false;   
  }   
  /** Always returns a user with no role. */   
  public IRbacUser getUser() {   
    return IRbacUser.NO_USER;   
  }   
  /** Always returns a null role set. */   
  public IRole[] getActiveRoles() {   
    return IRole.ZERO_ROLE;   
  }   
  public String toString() {   
    StringBuffer sb = new StringBuffer();   
    IRole[] role = getActiveRoles();   
//    p("role.length="+role.length);   
    for (int i=0; i < role.length; i++) {   
      sb.append(role[i].toString());   
//      p(role[i].toString());   
    }   
    return sb.toString();   
  }   
  /** Returns true iff the active role set contains the specified role. */   
  public boolean hasRole(IRole role) {   
    if (role == null) {   
      return false;   
    }   
    IRole[] r = getActiveRoles();   
    if (r == null || r.length == 0) {   
      return false;   
    }   
    for (int i=0; i < r.length; i++) {   
      if (r[i].equals(role)) {   
        return true;   
      }   
    }   
    return false;   
  }   
  public IPermission[] getPermissions() {   
    Set set = new HashSet();   
    IRole[] roles = getActiveRoles();   
    for (int i=0; i < roles.length; i++) {   
      IPermission[] perm = roles[i].getPermissions();   
      for (int j=0; j < perm.length; j++) {   
        set.add(perm[j]);   
      }   
    }   
    return (IPermission[])set.toArray(IPermission.ZERO_PERMISSION);   
  }   
  /**  
   * Returns true iff the active role set contains an active role  
   * with access privileges greater than or equal to that of the given role.  
   */   
/*  
  public boolean hasRoleGE(IRole role) {  
    if (role == null) {  
      return true;  
    }  
    IRole[] r = getActiveRoles();  
    if (r == null || r.length == 0) {  
      return false;  
    }  
    for (int i=0; i < r.length; i++) {  
      if (r[i].ge(role)) {  
        return true;  
      }  
    }  
    return false;  
  }  
  private void p(String s) {  
    System.out.println("AbstractRbacSession>>"+s);  
  }  
*/   
}  