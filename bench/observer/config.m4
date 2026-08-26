PHP_ARG_ENABLE([apmobs], [whether to enable apmobs], [--enable-apmobs])
if test "$PHP_APMOBS" != "no"; then
  PHP_NEW_EXTENSION(apmobs, apmobs.c, $ext_shared)
fi
