
   
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
/** A default implementation of the IPermission interface. */   
public class Permission extends AbstractPermission {   
  /** The current set of permission entries. */   
  private final IPermissionEntry[] entries;   
  /**  
   * Constructs with a set of permission entries.  
   * Note that client is responsible for ensuring there is no duplicate entries  
   * in the specified permission entry list.  
   */   
  public Permission(IPermissionEntry[] entries) {   
    this.entries = entries;   
  }   
  /**  
   * Constructs with a single permission entry.  
   * @param obj the target object.  
   * @param op the operation.  
   */   
  public Permission(Object obj, String op) {   
    this.entries = new IPermissionEntry[]{new PermissionEntry(obj, op)};   
  }   
  /**  
   * Constructs with a set of permission objects.  
   */   
  public Permission(IPermission[] p) {   
    Set set = new HashSet();   
    for (int i=0; i < p.length; i++) {   
      IPermissionEntry[] e = p[i].getPermissionEntries();   
      for (int j=0; j < e.length; j++) {   
        set.add(e[j]);   
      }   
    }   
    this.entries = (IPermissionEntry[])set.toArray(IPermissionEntry.ZERO_PERMISSION_ENTRY);   
  }   
  /** Returns the permission entry set of this permission. */   
  public IPermissionEntry[] getPermissionEntries() {   
    return entries;   
  }   
}   
