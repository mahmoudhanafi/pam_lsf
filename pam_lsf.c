/* pam_lsf module */

/*
 * $Id: pam_lsf.c,v 1.1 2005/02/01 $
 *
 * Written by Mahmoud Hanafi <hanafim@asc.hpc.mil>
 *
 */

#define DEFAULT_USER "nobody"

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <strings.h>
#include <sys/utsname.h>
#include <lsf/lsbatch.h>
#include <lsf/lsf.h>


/*
 * here, we make definitions for the externally accessible functions
 * in this file (these definitions are required for static modules
 * but strongly encouraged generally) they are used to instruct the
 * modules include file to define their prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>
#include <security/_pam_macros.h>

/* LSF Function to check for running jobs */
int lsf_check(char *username, char *hostname, int debug, int numtries)
{
   int options = CUR_JOB;
   int jobs, try;
   /* Inital LSF */

   if ( debug ) syslog(LOG_NOTICE,"pam_lsf.so: Init LSF \n");
   if (lsb_init("pam_lsf") < 0) {
                lsb_perror("check_user_host: lsb_init() failed");
                return 0;
   }
   for ( try = 0; try < numtries; try++ ) {
       if ( debug ) syslog(LOG_NOTICE,"pam_lsf.so: checking lsf user=%s host=%s try %d of %d \n",username,hostname,try,numtries);
       jobs = lsb_openjobinfo( 0, NULL, username, NULL, hostname, options);
       lsb_closejobinfo();
       if (jobs > 0) return 1;
       sleep(1);
   }
   syslog(LOG_NOTICE,"pam_lsf.so: user %s on host %s has no running jobs\n",username,hostname,try);
   return 0;
}

int pars_args(int argc, char **argv, int *debug, int *numtries)
{
        int i;
	int nt;
	/* 
	syslog(LOG_NOTICE," debug is %d, numtries is %d\n",*debug,*numtries);
	*/
	if ( argc < 1)
		return 1;
	for (i=0; i < argc; i++) {
		if ( strncasecmp(argv[i],"LSF_SERVERDIR",13 ) == 0 ) {
			/* syslog(LOG_NOTICE,"1 argv[%i] = %s\n",i,argv[i]); */
			putenv(argv[i]);
		}
		else if ( strncasecmp(argv[i],"LSF_ENVDIR",10 ) == 0 ) {
			/* syslog(LOG_NOTICE,"2 argv[%i] = %s\n",i,argv[i]); */
			putenv(argv[i]);
		}
		else if ( strncasecmp(argv[i],"DEBUG",sizeof("DEBUG") ) == 0 ) {
			/* syslog(LOG_NOTICE,"3 argv[%i] = %s\n",i,argv[i]); */
			*debug = 1;
		}
		else if ( atoi(argv[i]) != 0 ) {
			*numtries = atoi(argv[i]);
			/* syslog(LOG_NOTICE,"4 argv[%i] = %s, %d\n",i,argv[i],*numtries); */
		}
	}	
	/* 
	syslog(LOG_NOTICE," debug is %d, numtries is %d\n",*debug,*numtries);
	*/
	return 0;
}

/* --- authentication management functions --- */

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc
			,const char **argv)
{
    int retval;
    const char *user=NULL;
    struct utsname name;
    int debug, numtries;
    debug=0;
    numtries=5;

    if ( pars_args(argc, argv, &debug, &numtries) == 1 )
	syslog(LOG_ERR,"pam_lsf.so: Argument parsing failed\n");

    /*
    syslog(LOG_NOTICE," debug is %d, numtries is %d\n",debug,numtries);
    */
    if( debug)	syslog(LOG_NOTICE,"pam_lsf.so: parsing done, debug is %d, numtries id %d\n", debug, numtries);
    /*
     * authentication requires we know who the user wants to be
     */
    if ( debug ) syslog(LOG_NOTICE,"pam_lsf.so: Starting Auth\n");
    
    retval = pam_get_user(pamh, &user, NULL);
    if (retval != PAM_SUCCESS) {
	syslog(LOG_ERR,"pam_lsf.so: get user returned error: %s", pam_strerror(pamh,retval));
	return retval;
    }
    if (user == NULL || *user == '\0') {
	syslog(LOG_ERR,"pam_lsf.so:  username not known");
	retval = pam_set_item(pamh, PAM_USER, (const void *) DEFAULT_USER);
	if (retval != PAM_SUCCESS)
	    return PAM_USER_UNKNOWN;
    }

    if ( debug ) syslog(LOG_NOTICE,"pam_lsf.so: User name = %s\n",user);
    /* Get host name where we are running */
   if (uname (&name) == -1) {
        syslog(LOG_ERR,"pam_lsf.so: couldn't get hostname\n");
        return PAM_AUTH_ERR;
    }
    if ( debug ) syslog(LOG_NOTICE,"pam_lsf.so: Host name = %s\n",name.nodename);

    retval = lsf_check(user, name.nodename, debug, numtries);
    
    if ( debug ) syslog(LOG_NOTICE,"pam_lsf.so: lsf_check retval = %i\n",retval);

    if ( retval < 1 ) {
	syslog(LOG_NOTICE,"PAM_LSF.so: returing fail from auth\n");
        return PAM_AUTH_ERR;
    }
    else {
	syslog(LOG_NOTICE,"PAM_LSF.so: returing success from auth\n");
        return PAM_SUCCESS;
    }

    /* Never reach */
    return PAM_AUTH_ERR;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc
		   ,const char **argv)
{
     syslog(LOG_NOTICE,"PAM_LSF.so: returing success from setcred\n");
     return PAM_SUCCESS;
}

/* --- account management functions --- */

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc
		     ,const char **argv)
{
    int retval;
    const char *user=NULL;
    struct utsname name;
    int debug, numtries;
    debug=0;
    numtries=5;

    if ( pars_args(argc, argv, &debug, &numtries) == 1 )
        syslog(LOG_ERR,"pam_lsf.so: Argument parsing failed\n");

    /*
    syslog(LOG_NOTICE," debug is %d, numtries is %d\n",debug,numtries);
    */
    if( debug)	syslog(LOG_NOTICE,"pam_lsf.so: parsing done, debug is %d, numtries id %d\n", debug, numtries);
	
    if ( debug ) syslog(LOG_NOTICE,"pam_lsf.so: Starting acct_mgmt\n");
    
    retval = pam_get_user(pamh, &user, NULL);
    if (retval != PAM_SUCCESS) {
        syslog(LOG_ERR,"pam_lsf.so: get user returned error: %s", pam_strerror(pamh,retval));
        return retval;
    }
    if (user == NULL || *user == '\0') {
        syslog(LOG_ERR,"pam_lsf.so:  username not known");
        retval = pam_set_item(pamh, PAM_USER, (const void *) DEFAULT_USER);
        if (retval != PAM_SUCCESS)
            return PAM_USER_UNKNOWN;
    }
    if ( debug ) syslog(LOG_NOTICE,"pam_lsf.so: User name = %s\n",user);
    /* Get host name where we are running */
   if (uname (&name) == -1) {
        syslog(LOG_ERR,"pam_lsf.so: couldn't get hostname\n");
        return PAM_AUTH_ERR;
    }

    if ( debug ) syslog(LOG_NOTICE,"pam_lsf.so: Host name = %s\n",name.nodename);

    retval = lsf_check(user, name.nodename, debug, numtries);

    if ( debug ) syslog(LOG_NOTICE,"pam_lsf.so: lsf_check retval = %i\n",retval);

    if ( retval < 1 ) {
        syslog(LOG_NOTICE,"PAM_LSF.so: returing fail from acctmgt\n");
        return PAM_AUTH_ERR;
    }
    else {
        syslog(LOG_NOTICE,"PAM_LSF.so: returing success from acctmgt\n");
        return PAM_SUCCESS;
    }

    /* Never reach */
    return PAM_AUTH_ERR;

    syslog(LOG_NOTICE,"PAM_LSF.so: returing success from acctmgmt\n");
     return PAM_SUCCESS;
}

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_permit_modstruct = {
    "pam_permit",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    NULL,
    NULL,
    NULL
};

#endif

