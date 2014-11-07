<%-- 
    Document   : logout
    Created on : 2014-11-07, 10:56:36
    Author     : KLichorad
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>JSP Page</title>
    </head>
    <body>
<%
request.logout();
%>
        <h1>Wylogowano!</h1>
    </body>
</html>
