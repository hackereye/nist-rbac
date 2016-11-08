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
/** Role to which users and permissions can be assigned. */   
public interface IRole {   
  /** Role that has all permissons. */   
  public static final IRole SUPER_USER = new Role(new IPermission[]{IPermission.ALL_PERMISSION});   
  /** Role that has no permission. */   
  public static final IRole EMPTY_ROLE = new AbstractRole();   
  /** A null role set. */   
  public static final IRole[] ZERO_ROLE = new IRole[0];   
  /** Returns true iff this role is authorized with the specified permission. */   
  public boolean isAuthorized(IPermission perm);   
  /** Returns true iff this role is authorized with the specified permissions. */   
  public boolean isAuthorized(IPermission[] perm);   
  /**  
   * Returns the current set of permissions that have been assigned to this role.  
   * For advanced permission-role review.  
   */   
  public IPermission[] getPermissions();   
  /** Returns the attributes of this role. */   
  public Map getRoleAttributes();  // such as password associated with a role.   
  /**  
   * Returns true iff the access privilege of this role is  
   * greater than or equal to that of the given role.  
   */   
  public boolean ge(IRole role);   
  /** Returns the maximum number of users this role can be assigned to; or 0 if there is no maximum. */   
  public int getMaxMembers();   
  /**  
   * Returns the current list of users this role has been assigned to,  
   * either directly or indirectly via the role hierarchy.  
   * (A core RBAC feature.)  
   */   
  public IRbacUser[] getAssignedUsers();   
  /**  
   * Informs this role that it has just been added to the given user.  
   * @return true if this role can be successfully added to the given user;  
   * or false if this role has already been added.  
   * @throws RbacSecurityViolation if the maximum number of user that  
   * can be assigned to this role is exceeded.  
   */   
  public boolean roleAdded(IRbacUser user) throws RbacSecurityViolation;   
  /**  
   * Informs this role that it has just been removed from the given user.  
   * @return true if this role is successfully removed from the user;  
   * or false if there is nothing to remove.  
   */   
  public boolean roleDropped(IRbacUser user);   
  /**  
   * Grants the given permission to this role.  
   * @return true if the grant is successful;  
   * or false if the permission has already been granted.  
   */   
  public boolean grantPermission(IPermission perm);   
  /**  
   * Revokes the given permission from this role.  
   * @return true if the revokation is successful;  
   * or false if there is no such permission to revoke.  
   */   
  public boolean revokePermission(IPermission perm);   
}   