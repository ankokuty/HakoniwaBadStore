/**
 * NetBadstoreSoapSearchSoap.java
 *
 * This file was auto-generated from WSDL
 * by the Apache Axis 1.2 May 03, 2005 (02:20:24 EDT) WSDL2Java emitter.
 */

package net.badstore.www.cgi_bin.soapsearch_cgi;

public interface NetBadstoreSoapSearchSoap extends java.rmi.Remote {
    public void searchByNum(int sNum, javax.xml.rpc.holders.IntHolder item, javax.xml.rpc.holders.StringHolder sdesc, javax.xml.rpc.holders.StringHolder ldesc, javax.xml.rpc.holders.FloatHolder price) throws java.rmi.RemoteException;
    public void searchByName(java.lang.String sName, javax.xml.rpc.holders.IntHolder item, javax.xml.rpc.holders.StringHolder sdesc, javax.xml.rpc.holders.StringHolder ldesc, javax.xml.rpc.holders.FloatHolder price) throws java.rmi.RemoteException;
    public void searchByPrice(float sNum, javax.xml.rpc.holders.IntHolder item, javax.xml.rpc.holders.StringHolder sdesc, javax.xml.rpc.holders.StringHolder ldesc, javax.xml.rpc.holders.FloatHolder price) throws java.rmi.RemoteException;
}
