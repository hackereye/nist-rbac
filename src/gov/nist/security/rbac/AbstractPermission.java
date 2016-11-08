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
   
import  java.io.*;   
/**  
 * A permission base class that provides generic implemenation with no internal data set.  
 */   
public class AbstractPermission implements IPermission, Serializable {   
  /** Returns a null set of permission entry. */   
  public IPermissionEntry[] getPermissionEntries() {   
    return IPermissionEntry.ZERO_PERMISSION_ENTRY;   
  }   
  /** Returns a null set of role. */   
  public IRole[] getAssignedRoles () {   
    return  IRole.ZERO_ROLE;   
  }   
  /**  
   * Returns true iff this permission is greater than or equal to  
   * the given permission in terms of access privileges.  
   */   
  public boolean ge(IPermission p) {   
    if (p == null) {   
      return true;   
    }   
    if (p == this) {   
      return true;   
    }   
    IPermissionEntry[] to_pe = p.getPermissionEntries();   
   
    if (to_pe == null || to_pe.length == 0) {   
      return true;   
    }   
    IPermissionEntry[] pe = getPermissionEntries();   
  outter:   
    for (int i=0; i < to_pe.length; i++) {   
      IPermissionEntry pi = to_pe[i];   
      for (int j=0; j < pe.length; j++) {   
        IPermissionEntry pj = pe[j];   
        if (pj.ge(pi)) {   
          continue outter;   
        }   
      }   
      return false;   
    }   
    return true;   
  }   
  /** Two permissions are equal if they have the same set of permission entries. */   
  public boolean equals(Object o) {   
    if (o == null || !(o instanceof IPermission)) {   
      return false;   
    }   
    if (o == this) {   
      return true;   
    }   
    IPermission p = (IPermission)o;   
    IPermissionEntry[] pe = getPermissionEntries();   
    IPermissionEntry[] to_pe = p.getPermissionEntries();   
   
    if (pe == null && to_pe == null) {   
      return true;   
    }   
    if (pe == null || to_pe == null) {   
      return false;   
    }   
    if (pe.length != to_pe.length) {   
      return false;   
    }   
  outter:   
    for (int i=0; i < pe.length; i++) {   
      IPermissionEntry pi = pe[i];   
      for (int j=0; j < to_pe.length; j++) {   
        IPermissionEntry pj = to_pe[j];   
        if (pi.equals(pj)) {   
          continue outter;   
        }   
      }   
      return false;   
    }   
    return true;   
  }   
  public int hashCode() {   
    IPermissionEntry[] pe = getPermissionEntries();   
    int hashCode = 0;   
    if (pe != null) {   
      for (int i=0; i < pe.length; i++) {   
        hashCode ^= pe[i].hashCode();   
      }   
    }   
    return hashCode;   
  }   
  public String toString() {   
    StringBuffer sb = new StringBuffer();   
    IPermissionEntry[] p = getPermissionEntries();   
    for (int i=0; i < p.length; i++) {   
      sb.append("\n");   
      sb.append(p[i].toString());   
    }   
    return sb.toString();   
  }   
}  