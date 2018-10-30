package security;

import java.io.IOException;
import java.lang.reflect.Method;
import javax.annotation.Priority;
import javax.annotation.security.*;
import javax.ws.rs.*;
import javax.ws.rs.container.*;
import javax.ws.rs.core.*;
import javax.ws.rs.ext.Provider;

@Provider
@Priority(Priorities.AUTHORIZATION)
public class RolesAllowedFilter implements ContainerRequestFilter {

    @Context
    private ResourceInfo resourceInfo;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        Method resourceMethod = resourceInfo.getResourceMethod();

        // DenyAll on the method take precedence over RolesAllowed and PermitAll
        if (resourceMethod.isAnnotationPresent(DenyAll.class)) {
            throw new NotAuthorizedException("Resource Not Found");

        }

        // RolesAllowed on the method takes precedence over PermitAll
        RolesAllowed ra = resourceMethod.getAnnotation(RolesAllowed.class);
        if (assertRole(requestContext, ra)) {
            return;
        }

        // PermitAll takes precedence over RolesAllowed on the class
        if (resourceMethod.isAnnotationPresent(PermitAll.class)) {
            return;
        }

        if (resourceInfo.getResourceClass().isAnnotationPresent(DenyAll.class)) {
            throw new NotAuthorizedException("Resource Not Found");
        }

        // RolesAllowed on the class takes precedence over PermitAll
        ra = resourceInfo.getResourceClass().getAnnotation(RolesAllowed.class);
        if (assertRole(requestContext, ra)) {
            return;
        }
    }

    private boolean assertRole(ContainerRequestContext requestContext, RolesAllowed ra) {

        if (ra != null) {
            String[] roles = ra.value();
            for (String role : roles) {
                if (requestContext.getSecurityContext().isUserInRole(role)) {
                    return true;
                }
            }
            
            throw new NotAuthorizedException("You are not authorized to perform the requested operation", Response.Status.FORBIDDEN);
        }
        return false;
    }

}
