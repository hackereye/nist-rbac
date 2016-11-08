  
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
   
/** RBAC session is an active process representing a user. */   
public interface IRbacSession {   
  /** Returns true iff this session is authorized with the specified permission. */   
  public boolean isAuthorized(IPermission perm);   
  /** Returns true iff this session is authorized with the specified permissions. */   
  public boolean isAuthorized(IPermission[] perm);   
  /** Returns true iff this session is authorized with the permissions of the specified role. */   
  public boolean isAuthorized(IRole role);   
  /** Adds the given role to the current active role set. */   
  public boolean addActiveRole(IRole r);   
  /** Drops the given role from the current active role set. */   
  public boolean dropActiveRole(IRole r);   
  /** Returns the user of this session. */   
  public IRbacUser getUser();   
  /** Returns the current active role set. */   
  public IRole[] getActiveRoles();   
  /** Returns true iff the active role set contains the specified role. */   
  public boolean hasRole(IRole role);   
  /**  
   * Returns the set of permissions available in this session (ie. union of all  
   * permissions assigned to the active role set.  
   */   
  public IPermission[] getPermissions();   
  /**  
   * Returns true iff the active role set contains an active role  
   * with access privileges greater than or equal to that of the given role.  
   */   
//  public boolean hasRoleGE(IRole role);   
}   