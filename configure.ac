AC_INIT([libsodium-plugin], [1.0], [luckyfellow42@gmail.com])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([libsodium-plugin-config.h])

AM_INIT_AUTOMAKE([no-define foreign tar-ustar])

AM_MAINTAINER_MODE

AC_PROG_CC
AC_PROG_CPP
AC_PROG_LIBTOOL
	 
DC_DOVECOT
DC_DOVECOT_MODULEDIR
LIBDOVECOT_INCLUDE="$LIBDOVECOT_INCLUDE"
CFLAGS="$DOVECOT_CFLAGS"
LIBS="$DOVECOT_LIBS"
AC_SUBST(LIBDOVECOT_INCLUDE)

AC_CHECK_HEADER(sodium.h, [
  have_libsodium=yes
  AC_DEFINE(HAVE_LIBSODIUM,, [Define if you have the sodium library])
  LIBS="$LIBS -lsodium"
], [
    AC_ERROR([Can't build with libsodium support: sodium.h not found])
])

AC_CONFIG_FILES([
Makefile
src/Makefile
])

AC_OUTPUT
