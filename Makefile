CC = gcc 

LSF_TOPDIR = /usr/local/lsf/6.0
INCLUDE_DIR = ${LSF_TOPDIR}/include
LSF_LIBDIR = ${LSF_TOPDIR}/linux2.4-glibc2.3-x86/lib
#LIBS = -lnsl /usr/lib/libc_nonshared.a ${LSF_LIBDIR}/libbat.a ${LSF_LIBDIR}/liblsf.a 
LIBS = -lnsl ${LSF_LIBDIR}/libbat.a ${LSF_LIBDIR}/liblsf.a 
#CFLAGS = -g -DDEBUG
CFLAGS = -fPIC
LNKFLAGS =  -x -shared



SOURCE_FILES = pam_lsf.c
OBJECT_FILES = pam_lsf.o 


pam_lsf.so: $(OBJECT_FILES)
	gcc -shared -o pam_lsf.so $(OBJECT_FILES) $(LIBS)
#	ld -x --shared -o firstmod.so $(OBJECT_FILES) /usr/local/lsf/6.0/linux2.4-glibc2.3-x86/lib/libbat.a /usr/local/lsf/6.0/linux2.4-glibc2.3-x86/lib/liblsf.a -L$(LIBDIR) -lnsl
#	$(CC) -o check_user_host $(OBJECT_FILES) -L$(LIBDIR) -L${LSF_LIBDIR} $(LIBS)

pam_lsf.o: pam_lsf.c 
	$(CC) -c $(CFLAGS) pam_lsf.c -I$(INCLUDE_DIR) 

clean:
	rm -f pam_lsf.so pam_lsf.o core*
