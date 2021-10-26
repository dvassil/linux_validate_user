//
// https://stackoverflow.com/questions/17499163/how-to-check-password-in-linux-by-using-c-or-shell/63173069#63173069
//

#include <sys/types.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <string.h>
#include <stdio.h>

/// @return 0 - password is correct, otherwise no
int CheckPassword( const char* user, const char* password )
{
    struct passwd* passwdEntry = getpwnam( user );
    if ( !passwdEntry )
    {
        printf("{\"status\":\"error\",\"message\":\"User '%s' doesn't exist\"}", user);
        return 1;
    }

    if ( 0 != strcmp( passwdEntry->pw_passwd, "x" ) )
    {
        return strcmp( passwdEntry->pw_passwd, crypt( password, passwdEntry->pw_passwd ) );
    }
    else
    {
        // password is in shadow file
        struct spwd* shadowEntry = getspnam( user );
        if ( !shadowEntry )
        {
            printf("{\"status\":\"error\",\"message\":\"Failed to read shadow entry for user '%s'\"}", user);
            return 1;
        }

        return strcmp( shadowEntry->sp_pwdp, crypt( password, shadowEntry->sp_pwdp ) );
    }
}

int main(int argc, char*argv[])
{
    if (argc < 2 || argc > 3)
    {
        printf("{\"status\":\"error\",\"message\":\"Syntax: %s <username> [<password>]\"}", argv[0]);
        return 1;
    }

    const char* user = argv[1];
    const char* password = "";
    if (argc == 3)
    {
        password = argv[2];
    }

    if (0 != CheckPassword( user, password ))
    {
        printf("{\"status\":\"failed\",\"message\":\"User '%s' authentication failed\"}", user);
        return 1;
    }

    printf("{\"status\":\"success\",\"message\":\"User '%s' authenticated\"}", user);
    return 0;
}
