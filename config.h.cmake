/* Name of package */
#cmakedefine PACKAGE "${APPLICATION_NAME}"

/* Version number of package */
#cmakedefine VERSION "${APPLICATION_VERSION}"

#cmakedefine LOCALEDIR "${LOCALE_INSTALL_DIR}"
#cmakedefine DATADIR "${DATADIR}"
#cmakedefine LIBDIR "${LIBDIR}"
#cmakedefine PLUGINDIR "${PLUGINDIR}"
#cmakedefine SYSCONFDIR "${SYSCONFDIR}"
#cmakedefine BINARYDIR "${BINARYDIR}"
#cmakedefine SOURCEDIR "${SOURCEDIR}"

/************************** HEADER FILES *************************/

/* Define to 1 if you have the <pty.h> header file. */
#cmakedefine HAVE_PTY_H 1

/* Define to 1 if you have the <termios.h> header file. */
#cmakedefine HAVE_TERMIOS_H 1

/* Define to 1 if you have the <openssl/aes.h> header file. */
#cmakedefine HAVE_OPENSSL_AES_H 1

/* Define to 1 if you have the <openssl/blowfish.h> header file. */
#cmakedefine HAVE_OPENSSL_BLOWFISH_H 1

/* Define to 1 if you have the <openssl/des.h> header file. */
#cmakedefine HAVE_OPENSSL_DES_H 1

/*************************** FUNCTIONS ***************************/

/* Define to 1 if you have the `cfmakeraw' function. */
#cmakedefine HAVE_CFMAKERAW 1

/* Define to 1 if you have the `getaddrinfo' function. */
#cmakedefine HAVE_GETADDRINFO 1

/* Define to 1 if you have the `gethostbyname' function. */
#cmakedefine HAVE_GETHOSTBYNAME 1

/* Define to 1 if you have the `poll' function. */
#cmakedefine HAVE_POLL 1

/* Define to 1 if you have the `select' function. */
#cmakedefine HAVE_SELECT 1

/*************************** LIBRARIES ***************************/

/* Define to 1 if you have the `crypto' library (-lcrypto). */
#cmakedefine HAVE_LIBCRYPTO 1

/* Define to 1 if you have the `gcrypt' library (-lgcrypt). */
#cmakedefine HAVE_LIBGCRYPT 1

/* Define to 1 if you have the `z' library (-lz). */
#cmakedefine HAVE_LIBZ 1

/**************************** OPTIONS ****************************/

/* Define to 1 if you want to enable ZLIB */
#cmakedefine WITH_LIBZ 1

/* Define to 1 if you want to enable SSH1 */
#cmakedefine WITH_SFTP 1

/* Define to 1 if you want to enable SSH1 */
#cmakedefine WITH_SSH1 1

/* Define to 1 if you want to enable server support */
#cmakedefine WITH_SERVER 1

/* Define to 1 if you want to enable debug output for crypto functions */
#cmakedefine DEBUG_CRYPTO 1

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif
