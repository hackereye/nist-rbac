
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
   
import java.util.*;   
/** A default implementation of the IRole interface. */   
public class Role extends AbstractRole {   
  /** The "name" attribute key of this role. */   
  public static final String NAME = "name";   
  /** An unmodifiable set of permissions assigned to this role.*/   
  public final Set permSet;   
  /** An unmodifiable map of role attributes, such as name, desc, password, etc. */   
  public final Map attr;   
  /** Maximum number of user members of this role. */   
  public final int maxMembers;   
  /** The current set of users assigned with this role. */   
  private Set assignedUsers = Collections.synchronizedSet(new HashSet());   
  /** Constructs with the given permission. */   
  public Role(IPermission perm) {   
    this(new IPermission[]{perm}, null, 0);   
  }   
  /** Constructs with the given set of permissions. */   
  public Role(IPermission[] perm) {   
    this(perm, null, 0);   
  }   
  /** Constructs with the given sets of permissions and junior roles. */   
  public Role(IPermission[] perm, Map attr, int maxMembers) {   
    if (maxMembers < 0) {   
      throw new IllegalArgumentException("maxMembers must not be less than zero.");   
    }   
    this.maxMembers = maxMembers;   
    Set ps = new HashSet();   
   
    for (int i=0; i < perm.length; i++) {   
      ps.add(perm[i]);   
    }   
    this.permSet = ps;   
    this.attr = Collections.unmodifiableMap(attr == null ? new HashMap() : attr);   
  }   
  /** Returns true iff this role is authorized with the specified permission. */   
/*  
  public boolean isAuthorized(IPermission perm) {  
    if (perm == null  
        || perm == IPermission.NO_PERMISSION  
        || perm.equals(IPermission.NO_PERMISSION)) {  
        return true;  
    }  
    if (permSet.contains(IPermission.ALL_PERMISSION)) {  
      return true;  
    }  
    IPermissionEntry[] pe = perm.getPermissionEntries();  
  
  outter:  
    for (int i=0; i < pe.length; i++) {  
      for (Iterator itr=permSet.iterator(); itr.hasNext();) {  
        IPermission p = (IPermission)itr.next();  
        IPermissionEntry[] pe1 = p.getPermissionEntries();  
        for (int j=0; j < pe1.length; j++) {  
          if (pe1[j].ge(pe[i])) {  
            continue outter;  
          }  
        }  
      }  
      return false;  
    }  
    return true;  
//    return permSet.contains(perm);  
  }  
*/   
  /**  
   * Returns the current set of permissions that have been assigned to this role.  
   * For advanced permission-role review.  
   */   
  public IPermission[] getPermissions() {   
    synchronized(permSet) {   
      return (IPermission[])permSet.toArray(IPermission.ZERO_PERMISSION);   
    }   
  }   
  /**  
   * Returns the unmodifiable map of attributes of this role.  
   */   
  public Map getRoleAttributes() {   
    return attr;   
  }   
  /** Convenient method to return the name of this role. */   
  public String getName() {   
    return (String)attr.get(NAME);   
  }   
  /** Returns the maximum number of users this role can be assigned to; or zero if there is no limit. */   
  public int getMaxMembers () {   
    return  maxMembers;   
  }   
  //////////// Convenient methods. ///////////   
/*  
  public String getDesc() {  
    return (String)attr.get("desc");  
  }  
  public Object getAttr(String key) {  
    return attr.get(key);  
  }  
  private void p(String s) {  
    System.out.println("Role>>"+s);  
  }  
*/   
  /**  
   * Informs this role that it has just been added to the given user.  
   * @return true if this role can be successfully added to the given user;  
   * or false if this role has already been added.  
   * @throws RbacSecurityViolation if the maximum number of user that  
   * can be assigned to this role is exceeded.  
   */   
  public boolean roleAdded(IRbacUser user) throws RbacSecurityViolation {   
    if (maxMembers > 0 && assignedUsers.size() == maxMembers) {   
      throw new RbacSecurityViolation("More than "   
        + maxMembers + " users cannot be assigned to role " + this.getName());   
    }   
    return assignedUsers.add(user);   
  }   
  /**  
   * Informs this role that it has just been removed from the given user.  
   * @return true if this role is successfully removed from the user;  
   * or false if there is nothing to remove.  
   */   
  public boolean roleDropped(IRbacUser user) {   
    return assignedUsers.remove(user);   
  }   
  /**  
   * Returns the current set of users this role has been assigned to.  
   * (A core RBAC feature.)  
   */   
  public IRbacUser[] getAssignedUsers () {   
    synchronized(assignedUsers) {   
      return  (IRbacUser[])assignedUsers.toArray(IRbacUser.ZERO_USER);   
    }   
  }   
  /**  
   * Grants the given permission to this role.  
   * @return true if the grant is successful;  
   * or false if the permission has already been granted.  
   */   
  public boolean grantPermission(IPermission perm) {   
    if (perm == null) {   
      return false;   
    }   
    synchronized(permSet) {   
      return permSet.add(perm);   
    }   
  }   
  /**  
   * Revokes the given permission from this role.  
   * @return true if the revokation is successful;  
   * or false if there is no such permission to revoke.  
   */   
  public boolean revokePermission(IPermission perm) {   
    synchronized(permSet) {   
      return permSet.remove(perm);   
    }   
  }   
}   
