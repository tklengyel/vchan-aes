dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(vchan-aes-server, 1.0)
AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE()

AC_PROG_CC_STDC

PKG_CHECK_MODULES([CRYPTO], [libcrypto], [], [AC_MSG_ERROR([openssl has to be installed!])])
AC_SUBST([CRYPTO_CFLAGS])
AC_SUBST([CRYPTO_LIBS])

AC_CHECK_HEADER(pthread.h, [], [AC_MSG_ERROR([Xen header(s) missing!])])
AC_CHECK_LIB(pthread, [pthread_create], [], [AC_MSG_ERROR([pthread library is not functional!])])

AC_CHECK_HEADERS(
	[libxenvchan.h xenctrl.h xenstore.h],
	[], [AC_MSG_ERROR([Xen header(s) missing!])])

AC_CHECK_LIB(xenvchan, [libxenvchan_server_init], [], [AC_MSG_ERROR([libxenvchan library is not functional!])])
AC_CHECK_LIB(xenctrl, [xc_interface_open], [], [AC_MSG_ERROR([xenctrl library is not functional!])])
AC_CHECK_LIB(xenstore, [xs_transaction_start], [], [AC_ERROR([xenstore library is not functional!])])

AC_CONFIG_FILES(Makefile server/Makefile client/Makefile)
AC_OUTPUT

