Auth0 vNext WebApi implementation using Jwt tokens 

## Lessons learned:

 - RS256 JsonWebToken Token Signature Algorithm has to be used for this version of vNext (1.0.0 rc2)
 - app.UseMvc(); has to be put at the end of Startup.Configure method, otherwise the following exception would be thrown when using UseJwtBearerAuthentication:
 > System.InvalidOperationException: No authentication handler is configured to authenticate for the scheme: Bearer
