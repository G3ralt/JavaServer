package security;

import java.util.List;

public interface IUserFacade {

    /*
        Return the Roles if users could be authenticated, otherwise null
     */
    List<String> authenticateUser(String userName, String password);

    IUser getUserByUserId(String id);

}
