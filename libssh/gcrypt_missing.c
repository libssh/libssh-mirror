/* gcrypt_missing.c */
/* This file contains routines that are in OpenSSL but not in libgcrypt */

/*
Copyright 2003,04,06 Aris Adamantiadis

This file is part of the SSH Library

The SSH Library is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or (at your
option) any later version.

The SSH Library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
License for more details.

You should have received a copy of the GNU Lesser General Public License
along with the SSH Library; see the file COPYING.  If not, write to
the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
MA 02111-1307, USA. */
#include <stdlib.h>
#include "libssh/priv.h"

#ifdef HAVE_LIBGCRYPT
int my_gcry_dec2bn(bignum *bn, const char *data)
{
  int count;
  
  *bn = bignum_new();
  gcry_mpi_set_ui(*bn, 0);
  for (count = 0; data[count]; ++count)
  {
    gcry_mpi_mul_ui(*bn, *bn, 10);
    gcry_mpi_add_ui(*bn, *bn, data[count] - '0');
  }
  return count;
}

char *my_gcry_bn2dec(bignum bn)
{
  int count, count2;
  int size, rsize;
  char *ret;
  bignum bndup, num, ten;
  char decnum;
  
  size = gcry_mpi_get_nbits(bn) * 3;
  rsize = size / 10 + size / 1000 + 2;
  ret = malloc(rsize + 1);
  if (!gcry_mpi_cmp_ui(bn, 0))
    strcpy(ret, "0");
  else
  {
    for (bndup = gcry_mpi_copy(bn), ten = bignum_new(), num = bignum_new(),
	 bignum_set_word(ten, 10), count = rsize; count; --count)
    {
      gcry_mpi_div(bndup, num, bndup, ten, 0);
      for (decnum = 0, count2 = gcry_mpi_get_nbits(num); count2; decnum *= 2,
	   decnum += (gcry_mpi_test_bit(num, count2 - 1) ? 1 : 0), --count2)
	;
      ret[count - 1] = decnum + '0';
    }
    for (count = 0; count < rsize && ret[count] == '0'; ++count)
      ;
    for (count2 = 0; count2 < rsize - count; ++count2)
      ret[count2] = ret[count2 + count];
    ret[count2] = 0;
    bignum_free(num);
    bignum_free(bndup);
    bignum_free(ten);
  }
  return ret;
}
#endif
