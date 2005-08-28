AC_DEFUN(DC_DO_WIN32, [
  AC_CHECK_HEADERS(windows.h windowsx.h)
])

AC_DEFUN(DC_DO_TYPE, [
	if test -z "$ac_cv_sizeof_long"; then
		AC_C_INLINE
		AC_CHECK_SIZEOF(long long, 8)
		AC_CHECK_SIZEOF(long, 4)
		AC_CHECK_SIZEOF(int, 4)
		AC_CHECK_SIZEOF(short, 2)
	fi
	FOUND=0
	for dc_cv_loop in \$ac_cv_sizeof_long_long \$ac_cv_sizeof_int \$ac_cv_sizeof_long \$ac_cv_sizeof_short; do
		dc_cv_size=`eval echo $dc_cv_loop`
		dc_cv_name=`echo $dc_cv_loop | sed s/\\\$ac_cv_sizeof_//`
		if test "$dc_cv_size" = "$3"; then
			if test "$dc_cv_name" = "int"; then 
				AC_CHECK_TYPE($1, $2 int)
			fi
			if test "$dc_cv_name" = "long"; then
				AC_CHECK_TYPE($1, $2 long)
			fi
			if test "$dc_cv_name" = "long_long"; then
				AC_CHECK_TYPE($1, $2 long long)
			fi
			if test "$dc_cv_name" = "short"; then
				AC_CHECK_TYPE($1, $2 short)
			fi
			FOUND=1
			break
		fi
	done
])

dnl Usage:
dnl    DC_TEST_SHOBJFLAGS(shobjflags, shobjldflags, action-if-not-found)
dnl
AC_DEFUN(DC_TEST_SHOBJFLAGS, [
  AC_SUBST(SHOBJFLAGS)
  AC_SUBST(SHOBJLDFLAGS)

  OLD_LDFLAGS="$LDFLAGS"
  SHOBJFLAGS=""

  LDFLAGS="$OLD_LDFLAGS $1 $2"

  AC_TRY_LINK([#include <stdio.h>
int unrestst(void);], [ printf("okay\n"); unrestst(); return(0); ], [ SHOBJFLAGS="$1"; SHOBJLDFLAGS="$2" ], [
  LDFLAGS="$OLD_LDFLAGS"
  $3
])

  LDFLAGS="$OLD_LDFLAGS"
])

AC_DEFUN(DC_GET_SHOBJFLAGS, [
  AC_SUBST(SHOBJFLAGS)
  AC_SUBST(SHOBJLDFLAGS)

  AC_MSG_CHECKING(how to create shared objects)

  if test -z "$SHOBJFLAGS" -a -z "$SHOBJLDFLAGS"; then
    DC_TEST_SHOBJFLAGS([-fPIC -DPIC], [-shared -rdynamic], [
      DC_TEST_SHOBJFLAGS([-fPIC -DPIC], [-shared], [
	DC_TEST_SHOBJFLAGS([-fPIC -DPIC], [-shared -rdynamic -mimpure-text], [
	  DC_TEST_SHOBJFLAGS([-fPIC -DPIC], [-shared -mimpure-text], [
	    DC_TEST_SHOBJFLAGS([-fPIC -DPIC], [-shared -rdynamic -Wl,-G,-z,textoff], [
	      DC_TEST_SHOBJFLAGS([-fPIC -DPIC], [-shared -Wl,-G,-z,textoff], [
		DC_TEST_SHOBJFLAGS([-fPIC -DPIC], [-shared -dynamiclib -flat_namespace -undefined suppress -bind_at_load], [
		  DC_TEST_SHOBJFLAGS([-fPIC -DPIC], [-dynamiclib -flat_namespace -undefined suppress -bind_at_load], [
		    DC_TEST_SHOBJFLAGS([-fPIC -DPIC], [-Wl,-dynamiclib -Wl,-flat_namespace -Wl,-undefined,suppress -Wl,-bind_at_load], [
		      DC_TEST_SHOBJFLAGS([-fPIC -DPIC], [-dynamiclib -flat_namespace -undefined suppress], [
		        DC_TEST_SHOBJFLAGS([-fPIC -DPIC], [-dynamiclib], [
		          AC_MSG_RESULT(cant)
		          AC_MSG_ERROR([We are unable to make shared objects.])
                        ])
		      ])
		    ])
		  ])
		])
	      ])
	    ])
	  ])
	])
      ])
    ])
  fi

  AC_MSG_RESULT($SHOBJLDFLAGS $SHOBJFLAGS)

  DC_SYNC_SHLIBOBJS
])

AC_DEFUN(DC_SYNC_SHLIBOBJS, [
  AC_SUBST(SHLIBOBJS)
  SHLIBOBJS=""
  for obj in $LIB@&t@OBJS; do
    SHLIBOBJS="$SHLIBOBJS `echo $obj | sed 's/\.o$/_shr.o/g'`"
  done
])

AC_DEFUN(DC_CHK_OS_INFO, [
	AC_CANONICAL_HOST
	AC_SUBST(SHOBJEXT)
	AC_SUBST(SHOBJFLAGS)
	AC_SUBST(SHOBJLDFLAGS)
	AC_SUBST(CFLAGS)
	AC_SUBST(CPPFLAGS)
	AC_SUBST(AREXT)

	AC_MSG_CHECKING(host operating system)
	AC_MSG_RESULT($host_os)

	SHOBJEXT="so"
	AREXT="a"

	case $host_os in
		darwin*)
			SHOBJEXT="dylib"
			;;
		hpux*)
			SHOBJEXT="sl"
			;;
		mingw32msvc*)
			SHOBJEXT="dll"
			SHOBJFLAGS="-DPIC"
			CFLAGS="$CFLAGS -mno-cygwin -mms-bitfields"
			CPPFLAGS="$CPPFLAGS -mno-cygwin -mms-bitfields"
			SHOBJLDFLAGS='-shared -Wl,--enable-auto-image-base -Wl,--output-def,$[@].def,--out-implib,$[@].a'
			;;
		cygwin*)
			SHOBJEXT="dll"
			SHOBJFLAGS="-fPIC -DPIC"
			CFLAGS="$CFLAGS -mms-bitfields"
			CPPFLAGS="$CPPFLAGS -mms-bitfields"
			SHOBJLDFLAGS='-shared -Wl,--enable-auto-image-base -Wl,--output-def,$[@].def,--out-implib,$[@].a'
			;;

	esac
])


AC_DEFUN(DC_ASK_OPTLIB, [
  AC_ARG_WITH($5, [  --with-$5 $4], [
# Specified
    LIBSPEC=$withval
  ], [
# Not specified
    LIBSPECFLAGS=`pkg-config --libs $5 2>/dev/null`
    LIBSPECCFLAGS=`pkg-config --cflags $5 2>/dev/null`
    AC_CHECK_LIB($1, $2, [
      OLDCPPFLAGS="$CPPFLAGS"
      OLDCFLAGS="$CFLAGS"
      CPPFLAGS="$CPPFLAGS $LIBSPECCFLAGS"
      CFLAGS="$CFLAGS $LIBSPECCFLAGS"
      AC_CHECK_HEADER($3, [
	LIBSPEC=yes
      ], [
	LIBSPEC=no
      ])
      CPPFLAGS="$OLDCPPFLAGS"
      CFLAGS="$OLDCFLAGS"
    ], [
      LIBSPEC=no
      AC_MSG_WARN(Didn't find $5)
    ], $LIBSPECFLAGS)
  ])
  case $LIBSPEC in
  	no)
  		AC_MSG_WARN(Support for $5 disabled)
  		;;
  	*)
  		if test "${LIBSPEC}" = "yes"; then
			true
		else
			LIBSPECFLAGS="-L${LIBSPEC}/lib ${LIBSPECFLAGS}"
			LIBSPECCFLAGS="-I${LIBSPEC}/include ${LIBSPECCFLAGS}"
  		fi
		AC_CHECK_LIB($1, $2, [
		  OLDCFLAGS="$CFLAGS"
		  OLDCPPFLAGS="$CPPFLAGS"
		  CPPFLAGS="$CPPFLAGS ${LIBSPECCFLAGS}"
		  CFLAGS="$CFLAGS ${LIBSPECCFLAGS}"
  		  AC_CHECK_HEADER($3, [
		    if test -n "$7"; then
		      AC_DEFINE($7, [1], [Define to 1 if you have the <$3> header file.])
		    fi
		    if test -n "$6"; then
		      AC_DEFINE($6, [1], [Define to 1 if you have $2 from $5])
		    fi
		    LDFLAGS="$LDFLAGS $LIBSPECFLAGS"
		    LIBS="-l$1 $LIBS"
		  ], [
		    CFLAGS="$OLDCFLAGS"
		    CPPFLAGS="$OLDCPPFLAGS"
		    AC_MSG_ERROR(Could not find $3)
		  ])
		], [
		  AC_MSG_ERROR(Could not find $5)
		], $LIBSPECFLAGS)
  		;;
  esac
])

AC_DEFUN(DC_ASK_SMALL, [
	SMALL=0
	AC_ARG_ENABLE(small, AC_HELP_STRING([--enable-small], [Enable small build of libconfig. (disabled)]), [
		case $enableval in
			yes)            
				SMALL=1
				;;      
		esac    
	])

	if test $SMALL = 0; then
		dnl Use opennet if it's available AND not small
		DC_ASK_OPTLIB(opennet, fopen_net, opennet.h, [      Enable opennet support (auto)], libopennet, HAVE_LIBOPENNET, HAVE_OPENNET_H)
	else
		AC_DEFINE(ENABLE_SMALL, [1], [Define to 1 if you want to produce a minimalistic build.])
	fi
])
