/*
 * torture.c - torture library for testing libssh
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2008-2009 by Andreas Schneider <asn@cryptomilk.org>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>

#ifndef _WIN32
# include <dirent.h>
# include <errno.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "torture.h"
/* for pattern matching */
#include "match.c"

#define TORTURE_SSHD_SRV_IPV4 "127.0.0.10"
/* socket wrapper IPv6 prefix  fd00::5357:5fxx */
#define TORTURE_SSHD_SRV_IPV6 "fd00::5357:5f0a"
#define TORTURE_SSHD_SRV_PORT 22

static const char torture_rsa_testkey[] =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEArAOREUWlBXJAKZ5hABYyxnRayDZP1bJeLbPVK+npxemrhHyZ\n"
        "gjdbY3ADot+JRyWjvll2w2GI+3blt0j+x/ZWwjMKu/QYcycYp5HL01goxOxuusZb\n"
        "i+KiHRGB6z0EMdXM7U82U7lA/j//HyZppyDjUDniWabXQJge8ksGXGTiFeAJ/687\n"
        "uV+JJcjGPxAGFQxzyjitf/FrL9S0WGKZbyqeGDzyeBZ1NLIuaiOORyLGSW4duHLD\n"
        "N78EmsJnwqg2gJQmRSaD4BNZMjtbfiFcSL9Uw4XQFTsWugUDEY1AU4c5g11nhzHz\n"
        "Bi9qMOt5DzrZQpD4j0gA2LOHpHhoOdg1ZuHrGQIDAQABAoIBAFJTaqy/jllq8vZ4\n"
        "TKiD900wBvrns5HtSlHJTe80hqQoT+Sa1cWSxPR0eekL32Hjy9igbMzZ83uWzh7I\n"
        "mtgNODy9vRdznfgO8CfTCaBfAzQsjFpr8QikMT6EUI/LpiRL1UaGsNOlSEvnSS0Z\n"
        "b1uDzAdrjL+nsEHEDJud+K9jwSkCRifVMy7fLfaum+YKpdeEz7K2Mgm5pJ/Vg+9s\n"
        "vI2V1q7HAOI4eUVTgJNHXy5ediRJlajQHf/lNUzHKqn7iH+JRl01gt62X8roG62b\n"
        "TbFylbheqMm9awuSF2ucOcx+guuwhkPir8BEMb08j3hiK+TfwPdY0F6QH4OhiKK7\n"
        "MTqTVgECgYEA0vmmu5GOBtwRmq6gVNCHhdLDQWaxAZqQRmRbzxVhFpbv0GjbQEF7\n"
        "tttq3fjDrzDf6CE9RtZWw2BUSXVq+IXB/bXb1kgWU2xWywm+OFDk9OXQs8ui+MY7\n"
        "FiP3yuq3YJob2g5CCsVQWl2CHvWGmTLhE1ODll39t7Y1uwdcDobJN+ECgYEA0LlR\n"
        "hfMjydWmwqooU9TDjXNBmwufyYlNFTH351amYgFUDpNf35SMCP4hDosUw/zCTDpc\n"
        "+1w04BJJfkH1SNvXSOilpdaYRTYuryDvGmWC66K2KX1nLErhlhs17CwzV997nYgD\n"
        "H3OOU4HfqIKmdGbjvWlkmY+mLHyG10bbpOTbujkCgYAc68xHejSWDCT9p2KjPdLW\n"
        "LYZGuOUa6y1L+QX85Vlh118Ymsczj8Z90qZbt3Zb1b9b+vKDe255agMj7syzNOLa\n"
        "/MseHNOyq+9Z9gP1hGFekQKDIy88GzCOYG/fiT2KKJYY1kuHXnUdbiQgSlghODBS\n"
        "jehD/K6DOJ80/FVKSH/dAQKBgQDJ+apTzpZhJ2f5k6L2jDq3VEK2ACedZEm9Kt9T\n"
        "c1wKFnL6r83kkuB3i0L9ycRMavixvwBfFDjuY4POs5Dh8ip/mPFCa0hqISZHvbzi\n"
        "dDyePJO9zmXaTJPDJ42kfpkofVAnfohXFQEy+cguTk848J+MmMIKfyE0h0QMabr9\n"
        "86BUsQKBgEVgoi4RXwmtGovtMew01ORPV9MOX3v+VnsCgD4/56URKOAngiS70xEP\n"
        "ONwNbTCWuuv43HGzJoVFiAMGnQP1BAJ7gkHkjSegOGKkiw12EPUWhFcMg+GkgPhc\n"
        "pOqNt/VMBPjJ/ysHJqmLfQK9A35JV6Cmdphe+OIl28bcKhAOz8Dw\n"
        "-----END RSA PRIVATE KEY-----\n";

static const char torture_rsa_testkey_pub[] =
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsA5ERRaUFckApnmEAFjLGdFrIN"
        "k/Vsl4ts9Ur6enF6auEfJmCN1tjcAOi34lHJaO+WXbDYYj7duW3SP7H9lbCMwq79B"
        "hzJxinkcvTWCjE7G66xluL4qIdEYHrPQQx1cztTzZTuUD+P/8fJmmnIONQOeJZptd"
        "AmB7ySwZcZOIV4An/rzu5X4klyMY/EAYVDHPKOK1/8Wsv1LRYYplvKp4YPPJ4FnU0"
        "si5qI45HIsZJbh24csM3vwSawmfCqDaAlCZFJoPgE1kyO1t+IVxIv1TDhdAVOxa6B"
        "QMRjUBThzmDXWeHMfMGL2ow63kPOtlCkPiPSADYs4ekeGg52DVm4esZ "
        "aris@aris-air\n";

static const char torture_rsa_testkey_cert[] =
        "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNz"
        "aC5jb20AAAAgL77S/SgY969FbEtNBsbLvvtGFgnEHaPb+V7ajwuf+R0AAAADAQABA"
        "AABAQCsA5ERRaUFckApnmEAFjLGdFrINk/Vsl4ts9Ur6enF6auEfJmCN1tjcAOi34"
        "lHJaO+WXbDYYj7duW3SP7H9lbCMwq79BhzJxinkcvTWCjE7G66xluL4qIdEYHrPQQ"
        "x1cztTzZTuUD+P/8fJmmnIONQOeJZptdAmB7ySwZcZOIV4An/rzu5X4klyMY/EAYV"
        "DHPKOK1/8Wsv1LRYYplvKp4YPPJ4FnU0si5qI45HIsZJbh24csM3vwSawmfCqDaAl"
        "CZFJoPgE1kyO1t+IVxIv1TDhdAVOxa6BQMRjUBThzmDXWeHMfMGL2ow63kPOtlCkP"
        "iPSADYs4ekeGg52DVm4esZAAAAAAAAAAAAAAABAAAADmxpYnNzaF90b3J0dXJlAAA"
        "AAAAAAAAAAAAA//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRp"
        "bmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtc"
        "G9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdX"
        "Nlci1yYwAAAAAAAAAAAAABFwAAAAdzc2gtcnNhAAAAAwEAAQAAAQEAoowcv2Gn8tO"
        "eDyw/lgdMpoBsLtHTTdVVOOo5HwMFvj/lFkbZlb6J2n9GIE64HNPE45vSnIdJZwz4"
        "UYfTvtnNKNHp1MgMrjK1Z6EjyZsGqDZ+BhmvcKA6IckkhBJnDV7U9dMrovAWha61Z"
        "9GpDqB1naRfbwqJQwSRHF1p71Cnf0fZKxOhAVx0ophmYGz3x3qq4PeOZv3Yl0AHTV"
        "dRmqmeELDUxeuXN2bgSyb881zEgdaKHH5oWySykP4uwjn6T7ETuL2MsDdG3HZHDhn"
        "LzLmfzOZ/cNadMCrgauMluQKc5dYF2TSeDaUxwun/NPMQBVZdETHLAMBgkGmhRUku"
        "flVDIQAAAQ8AAAAHc3NoLXJzYQAAAQADSp4b/Zta8zs6v47iwmxV2Gbucvt1kDrvT"
        "vKAKSbGN0+zoMyXiNfMHM/OvZObDS/WWGs4GMRqbJavwO3ja/dQY17oJss23lZ+Rc"
        "Lw4Rqsi3/ZEPCnX6ficiRS/yRN/LAkoXvx9vBx9QHfxlzF6JXq07wTt21zxW0tntd"
        "8dL+JI9ZZ9YylnxF3gHqfRFe2ahJpiywmxm0yOZgDmimOhep59i6BH5zHiPALvpge"
        "Mbk075oA5K9XKsHTflCcsQRQH+pXqaNQGL37z2CFz9oezxQYvIqqKF0w/eeRIARoA"
        "neB6OdgTpKFsmgPZVtqrvhjw+b5T8a4W4iWSl+6wg6gowAm "
        "rsa_privkey.pub\n";

static const char torture_dsa_testkey[] =
        "-----BEGIN DSA PRIVATE KEY-----\n"
        "MIIBuwIBAAKBgQCUyvVPEkn3UnZDjzCzSzSHpTltzr0Ec+1mz/JACjHMBJ9C/W/P\n"
        "wvH3yjkfoFhhREvoY7IPnwAu5bcxw8TkISq7YROQ409PqwwPvy0N3GUp/+kKS268\n"
        "BIJ+VKN513XRf7eL1e4aHUJ+al9x1JxTmc6T0GBq1lyu+CTUUyh25aNDFwIVAK84\n"
        "j20GmU+zewjQwsIXuVb6C/PHAoGAXhuIVsJxUQJ5nWQRLf7o3XEGQ+EcVmHOzMB1\n"
        "xCsHjYnpEhhco+r/HDZSD31kzDeAZUycz31WqGL8yXr+OZRLqEsGC7dwEAzPiXDu\n"
        "l0zHcl0yiKPrRrLgNJHeKcT6JflBngK7jQRIVUg3F3104fbVa2rwaniLl4GSBZPX\n"
        "MpUdng8CgYB4roDQBfgf8AoSAJAb7y8OVvxt5cT7iqaRMQX2XgtW09Nu9RbUIVS7\n"
        "n2mw3iqZG0xnG3iv1oL9gwNXMLlf+gLmsqU3788jaEZ9IhZ8VdgHAoHm6UWM7b2u\n"
        "ADmhirI6dRZUVO+/iMGUvDxa66OI4hDV055pbwQhtxupUatThyDzIgIVAI1Hd8/i\n"
        "Pzsg7bTzoNvjQL+Noyiy\n"
        "-----END DSA PRIVATE KEY-----\n";

static const char torture_dsa_testkey_pub[] =
        "ssh-dss AAAAB3NzaC1kc3MAAACBAJTK9U8SSfdSdkOPMLNLNIelOW3OvQRz7WbP8k"
        "AKMcwEn0L9b8/C8ffKOR+gWGFES+hjsg+fAC7ltzHDxOQhKrthE5DjT0+rDA+/LQ3c"
        "ZSn/6QpLbrwEgn5Uo3nXddF/t4vV7hodQn5qX3HUnFOZzpPQYGrWXK74JNRTKHblo0"
        "MXAAAAFQCvOI9tBplPs3sI0MLCF7lW+gvzxwAAAIBeG4hWwnFRAnmdZBEt/ujdcQZD"
        "4RxWYc7MwHXEKweNiekSGFyj6v8cNlIPfWTMN4BlTJzPfVaoYvzJev45lEuoSwYLt3"
        "AQDM+JcO6XTMdyXTKIo+tGsuA0kd4pxPol+UGeAruNBEhVSDcXfXTh9tVravBqeIuX"
        "gZIFk9cylR2eDwAAAIB4roDQBfgf8AoSAJAb7y8OVvxt5cT7iqaRMQX2XgtW09Nu9R"
        "bUIVS7n2mw3iqZG0xnG3iv1oL9gwNXMLlf+gLmsqU3788jaEZ9IhZ8VdgHAoHm6UWM"
        "7b2uADmhirI6dRZUVO+/iMGUvDxa66OI4hDV055pbwQhtxupUatThyDzIg== "
        "aris@aris-air\n";

static const char torture_dsa_testkey_cert[] =
        "ssh-dss-cert-v01@openssh.com AAAAHHNzaC1kc3MtY2VydC12MDFAb3BlbnNza"
        "C5jb20AAAAgKAd9MpIBrzctQyJvCYYJ2WUD5fyWlXMSv1G/3VihbCAAAACBAJTK9U8"
        "SSfdSdkOPMLNLNIelOW3OvQRz7WbP8kAKMcwEn0L9b8/C8ffKOR+gWGFES+hjsg+fA"
        "C7ltzHDxOQhKrthE5DjT0+rDA+/LQ3cZSn/6QpLbrwEgn5Uo3nXddF/t4vV7hodQn5"
        "qX3HUnFOZzpPQYGrWXK74JNRTKHblo0MXAAAAFQCvOI9tBplPs3sI0MLCF7lW+gvzx"
        "wAAAIBeG4hWwnFRAnmdZBEt/ujdcQZD4RxWYc7MwHXEKweNiekSGFyj6v8cNlIPfWT"
        "MN4BlTJzPfVaoYvzJev45lEuoSwYLt3AQDM+JcO6XTMdyXTKIo+tGsuA0kd4pxPol+"
        "UGeAruNBEhVSDcXfXTh9tVravBqeIuXgZIFk9cylR2eDwAAAIB4roDQBfgf8AoSAJA"
        "b7y8OVvxt5cT7iqaRMQX2XgtW09Nu9RbUIVS7n2mw3iqZG0xnG3iv1oL9gwNXMLlf+"
        "gLmsqU3788jaEZ9IhZ8VdgHAoHm6UWM7b2uADmhirI6dRZUVO+/iMGUvDxa66OI4hD"
        "V055pbwQhtxupUatThyDzIgAAAAAAAAAAAAAAAQAAAA5saWJzc2hfdG9ydHVyZQAAA"
        "AAAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5"
        "nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvc"
        "nQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXI"
        "tcmMAAAAAAAAAAAAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBAKKMHL9hp/LTng8sP"
        "5YHTKaAbC7R003VVTjqOR8DBb4/5RZG2ZW+idp/RiBOuBzTxOOb0pyHSWcM+FGH077"
        "ZzSjR6dTIDK4ytWehI8mbBqg2fgYZr3CgOiHJJIQSZw1e1PXTK6LwFoWutWfRqQ6gd"
        "Z2kX28KiUMEkRxdae9Qp39H2SsToQFcdKKYZmBs98d6quD3jmb92JdAB01XUZqpnhC"
        "w1MXrlzdm4Esm/PNcxIHWihx+aFskspD+LsI5+k+xE7i9jLA3Rtx2Rw4Zy8y5n8zmf"
        "3DWnTAq4GrjJbkCnOXWBdk0ng2lMcLp/zTzEAVWXRExywDAYJBpoUVJLn5VQyEAAAE"
        "PAAAAB3NzaC1yc2EAAAEAAt4V9aGqeahOfUvhG7M8/Mn26aLB/HXbICYFJF7dY6urm"
        "SIoS2KBqISCFGXTituiwGlZeAJ+pVgCMYo07Nxtd6oqIjsgKfJqDNx7e4pGw/YJnkm"
        "BqMO/k/ygu2mLmQF0lnpmG2KyjKEljMibHaKlFkcVNbwfOb4p8N3OHm66g5mbCUTRZ"
        "DHqMSJb3YtnObLexD13RydwxkG5AfCnOWxy5O4agXGEYwr/48AQBHYg9obGtpD1qyF"
        "4mMXgzaLViFtcwah6wHGlW0UPQMvrq/RqigAkyUszSccfibkIXJ+wGAgsRYhVAMwME"
        "JqPZ6GHOEIjLBKUegsclHb7Pk0YO8Auaw== "
        "aris@aris-air\n";

static const char torture_rsa_testkey_pp[] =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        "DEK-Info: AES-128-CBC,5375534F40903DD66B3851A0DA03F6FA\n"
        "\n"
        "m5YYTNOMd1xCKfifwCX4R1iLJoAc4cn1aFiL7f2kBbfE2jF1LTQBJV1h1CqYZfAB\n"
        "WtM/7FkQPnKXqsMndP+v+1Xc+PYigE3AezJj/0g7xn/zIBwGjkLAp435AdL5i6Fg\n"
        "OhOL8LyolRrcGn17jE4S4iGbzw8PVyfzNzdj0Emwql5F6M7pgLbInRNKM/TF4z2h\n"
        "b6Pi9Bw43dwaJ7wiiy/vo/v4MyXsJBoeKbc4VCmxiYFvAYCvVFlDkyIw/QnR3MKQ\n"
        "g/Zsk7Pw3aOioxk6LJpZ5x0tO23nXDG1aOZHWykI0BpJV+LIpD2oSYOHJyVO83XT\n"
        "RQUMSTXc2K2+ejs0XQoLt/GxDDHe+8W8fWQK3C7Lyvl9oKjmb5sTWi3mdSv0C+zR\n"
        "n5KSVbUKNXrjix7qPKkv5rWqb84CKVnCMb7tWaPLR19nQqKVYBIs6v0OTTvS6Le7\n"
        "lz4lxBkcUy6vi0tWH9MvLuT+ugdHLJZ4UXBthCgV58pM1o+L+WMIl+SZXckiCAO3\n"
        "7ercA57695IA6iHskmr3eazJsYFEVFdR/cm+IDy2FPkKmJMjXeIWuh3yASBk7LBR\n"
        "EQq3CC7AioO+Vj8m/fEIiNZJSQ6p0NmgnPoO3rTYT/IobmE99/Ht6oNLmFX4Pr7e\n"
        "F4CGWKzwxWpCnw2vVolCFByASmZycbJvrIonZBKY1toU28lRm4tCM6eCNISVLMeE\n"
        "VtQ+1PH9/2KZspZl+SX/kjV3egggy0TFKRU8EcYPJFC3Vpy+shEai35KBVo44Z18\n"
        "apza7exm3igNEqOqe07hLs3Bjhvk1oS+WhMbAG9ARTOKuyBOJh/ZV9tFMNZ6v+q5\n"
        "TofgNcIhNYNascymU1io18xTW9c3RRcmRKqIWnj4EH8o7Aojv/l+zvdV7/GVlR4W\n"
        "pR9cuJEiyiEjS46axoc6dSOtdnvag+BpFQb+lGY97F9nNGyBdtLD5ASVh5OVG4fu\n"
        "Pf0O7Bdj1kIuBhV8axE/slf6UHANiodeqkR9B24+0Cy+miPiHazzUkbdSJ4r03g5\n"
        "J1Y5S8qbl9++sqhQMLMUkeK4pDWh1aocA9bDA2RcBNuXGiZeRFUiqxcBS+iO418n\n"
        "DFyWz4UfI/m1IRSjoo/PEpgu5GmosUzs3Dl4nAcf/REBEX6M/kKKxHTLjE8DxDsz\n"
        "fn/vfsXV3s0tbN7YyJdP8aU+ApZntw1OF2TS2qS8CPWHTcCGGTab5WEGC3xFXKp0\n"
        "uyonCxV7vNLOiIiHdQX+1bLu7ps7GBH92xGkPg7FrNNcMc07soP7jjjB578n9Gpl\n"
        "cIDBdgovTRFHiWu3yRspVt0zPfMJB/hqn+IAp98wfvjl8OZM1ZZkejnwXnQil5ZU\n"
        "wjEBEtx+nX56vdxipzKoHh5yDXmPbNajBYkg3rXJrLFh3Tsf0CzHcLdHNz/qJ9LO\n"
        "wH16grjR1Q0CzCW3FAv0Q0euqkXac+TfuIg3HiTPrBPnJQW1uivrx1F5tpO/uboG\n"
        "h28LwqJLYh+1T0V//uiy3SMATpYKvzg2byGct9VUib8QVop8LvVF/n42RaxtTCfw\n"
        "JSvUyxoaZUjQkT7iF94HsF+FVVJdI55UjgnMiZ0d5vKffWyTHYcYHkFYaSloAMWN\n"
        "-----END RSA PRIVATE KEY-----\n";

static const char torture_dsa_testkey_pp[] =
        "-----BEGIN DSA PRIVATE KEY-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        "DEK-Info: AES-128-CBC,266023B64B1B814BCD0D0E477257F06D\n"
        "\n"
        "QJQErZrvYsfeMNMnU+6yVHH5Zze/zUFdPip7Bon4T1wCGlVasn4x/GQcMm1+mgmb\n"
        "PCK/qJ5qw9nCepLYJq2xh8gohbwF/XKxeaNGcRA2+ancTooDUjeRTlk1WRtS1+bq\n"
        "LBkwhxLXW26lIuQUHzfi93rRqQI2LC4McngY7L7WVJer7sH7hk5//4Gf6zHtPEl+\n"
        "Tr2ub1zNrVbh6e1Bitw7DaGZNX6XEWpyTTsAd42sQWh6o23MC6GyfS1YFsPGHzGe\n"
        "WYQbWn2AZ1mK32z2mLZfVg41qu9RKG20iCyaczZ2YmuYyOkoLHijOAHC8vZbHwYC\n"
        "+lN9Yc8/BoMuMMwDTMDaJD0TsBX02hi9YI7Gu88PMCJO+SRe5400MonUMXTwCa91\n"
        "Tt3RhYpBzx2XGOq5199+oLdTJAaXHJcuB6viKNdSLBuhx6RAEJXZnVexchaHs4Q6\n"
        "HweIv6Et8MjVoqwkaQDmcIGA73qZ0lbUJFZAu2YDJ6TpHc1lHZes763HoMYfuvkX\n"
        "HTSuHZ7edjoWqwnl/vkc3+nG//IEj8LqAacx0i4krDcQpGuQ6BnPfwPFco2NQQpw\n"
        "wHBOL6HrOnD+gGs6DUFwzA==\n"
        "-----END DSA PRIVATE KEY-----\n";

static const char torture_ecdsa256_testkey[] =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEIBCDeeYYAtX3EnsP0ratwVpNTaA/4K1N6VvHMiUZlVdhoAoGCCqGSM49\n"
        "AwEHoUQDQgAEx+9ud88Q5GWtLd+yMtYaapC85g+2ZLp7VtFHA0EbNHqBUQxoh+Ik\n"
        "89Mlr7AUxcFPd+kCo+NE6yq/mNQcL7E6iQ==\n"
        "-----END EC PRIVATE KEY-----\n";

static const char torture_ecdsa256_testkey_pub[] =
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNT"
        "YAAABBBMfvbnfPEORlrS3fsjLWGmqQvOYPtmS6e1bRRwNBGzR6gVEMaIfiJPPTJa+w"
        "FMXBT3fpAqPjROsqv5jUHC+xOok= aris@kalix86\n";

static const char torture_ecdsa384_testkey[] =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MIGkAgEBBDBY8jEa5DtRy4AVeTWhPJ/TK257behiC3uafEi6YA2oHORibqX55EDN\n"
        "wz29MT40mQSgBwYFK4EEACKhZANiAARXc4BN6BrVo1QMi3+i/B85Lu7SMuzBi+1P\n"
        "bJti8xz+Szgq64gaBGOK9o+WOdLAd/w7p7DJLdztJ0bYoyT4V3B3ZqR9RyGq6mYC\n"
        "jkXlc5YbYHjueBbp0oeNXqsXHNAWQZo=\n"
        "-----END EC PRIVATE KEY-----\n";

static const char torture_ecdsa384_testkey_pub[] =
        "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzOD"
        "QAAABhBFdzgE3oGtWjVAyLf6L8Hzku7tIy7MGL7U9sm2LzHP5LOCrriBoEY4r2j5Y5"
        "0sB3/DunsMkt3O0nRtijJPhXcHdmpH1HIarqZgKOReVzlhtgeO54FunSh41eqxcc0B"
        "ZBmg== aris@kalix86";

static const char torture_ecdsa521_testkey[] =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MIHbAgEBBEG83nSJ2SLoiBvEku1JteQKWx/Xt6THksgC7rrIaTUmNzk+60f0sCCm\n"
        "Gll0dgrZLmeIw+TtnG1E20VZflCKq+IdkaAHBgUrgQQAI6GBiQOBhgAEAc6D728d\n"
        "baQkHnSPtztaRwJw63CBl15cykB4SXXuwWdNOtPzBijUULMTTvBXbra8gL4ATd9d\n"
        "Qnuwn8KQUh2T/z+BARjWPKhcHcGx57XpXCEkawzMYaHUUnRdeFEmNRsbXypsf0mJ\n"
        "KATU3h8gzTMkbrx8DJTFHEIjXBShs44HsSYVl3Xy\n"
        "-----END EC PRIVATE KEY-----\n";

static const char torture_ecdsa521_testkey_pub[] =
        "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1Mj"
        "EAAACFBAHOg+9vHW2kJB50j7c7WkcCcOtwgZdeXMpAeEl17sFnTTrT8wYo1FCzE07w"
        "V262vIC+AE3fXUJ7sJ/CkFIdk/8/gQEY1jyoXB3Bsee16VwhJGsMzGGh1FJ0XXhRJj"
        "UbG18qbH9JiSgE1N4fIM0zJG68fAyUxRxCI1wUobOOB7EmFZd18g== aris@kalix86";

static const char torture_ed25519_testkey[]=
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
        "QyNTUxOQAAACAVlp8bgmIjsrzGC7ZIKBMhCpS1fpJTPgVOjYdz5gIqlwAAAJBzsDN1c7Az\n"
        "dQAAAAtzc2gtZWQyNTUxOQAAACAVlp8bgmIjsrzGC7ZIKBMhCpS1fpJTPgVOjYdz5gIqlw\n"
        "AAAEBgYXKi3utbZKlYyByhM8Ad6CDWrEh1hmyFl0FnCz5hjRWWnxuCYiOyvMYLtkgoEyEK\n"
        "lLV+klM+BU6Nh3PmAiqXAAAADGFyaXNAa2FsaXg4NgE=\n"
        "-----END OPENSSH PRIVATE KEY-----\n";

static const char torture_ed25519_testkey_pub[]=
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBWWnxuCYiOyvMYLtkgoEyEKlLV+klM+"
        "BU6Nh3PmAiqX aris@kalix86";

static const char torture_ed25519_testkey_pp[]=
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABB3FWpQcE\n"
        "KHKq6PcjkxjmKzAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIOGFVuOyZBL0T+NR\n"
        "C7qEV9qr6QiGhz2XSXrxuQoU84FgAAAAkBlOVfS5U7FxtBEtxfxQhZjrZAj2z9d4OfGRPl\n"
        "ZfCnAJNEM3BZ3XCabsujhMkqEs9eptRfj41X6NA8aSFs5JYT+JFVfg470FKtpyUmAibMIo\n"
        "JzI41zAncFd1x7bAgO5HBDe3xNsV159D+sXRkWB9Tzk0l4F8SZvInheIS7VSbqH7t1+yDB\n"
        "Y3GsmYTDstmicanQ==\n"
        "-----END OPENSSH PRIVATE KEY-----\n";

static const char torture_rsa_certauth_pub[]=
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCnA2n5vHzZbs/GvRkGloJNV1CXHI"
        "S5Xnrm05HusUJSWyPq3I1iCMHdYA7oezHa9GCFYbIenaYPy+G6USQRjYQz8SvAZo06"
        "SFNeJSsa1kAIqxzdPT9kBrRrYK39PZQPsYVfRPqZBdmc+jwrfz97IFEJyXMI47FoTG"
        "kgEq7eu3z2px/tdIZ34I5Hr5DDBxicZi4jluyRUJHfSPoBxyhF7OkPX4bYkrc691je"
        "IQDxubl650WYLHgFfad0xTzBIFE6XUb55Dp5AgRdevSoso1Pe0IKFxxMVpP664LCbY"
        "K06Lv6kcotfFlpvUtR1yx8jToGcSoq5sSzTwvXSHCQQ9ZA1hvF "
        "torture_certauth_key";

#define TORTURE_SOCKET_DIR "/tmp/test_socket_wrapper_XXXXXX"
#define TORTURE_SSHD_PIDFILE "sshd/sshd.pid"
#define TORTURE_SSHD_CONFIG "sshd/sshd_config"
#define TORTURE_PCAP_FILE "socket_trace.pcap"

static int verbosity = 0;
static const char *pattern = NULL;

#ifndef _WIN32
static int _torture_auth_kbdint(ssh_session session,
                               const char *password) {
    const char *prompt;
    char echo;
    int err;

    if (session == NULL || password == NULL) {
        return SSH_AUTH_ERROR;
    }

    err = ssh_userauth_kbdint(session, NULL, NULL);
    if (err == SSH_AUTH_ERROR) {
        return err;
    }

    if (ssh_userauth_kbdint_getnprompts(session) != 1) {
        return SSH_AUTH_ERROR;
    }

    prompt = ssh_userauth_kbdint_getprompt(session, 0, &echo);
    if (prompt == NULL) {
        return SSH_AUTH_ERROR;
    }

    if (ssh_userauth_kbdint_setanswer(session, 0, password) < 0) {
        return SSH_AUTH_ERROR;
    }
    err = ssh_userauth_kbdint(session, NULL, NULL);
    if (err == SSH_AUTH_INFO) {
        if (ssh_userauth_kbdint_getnprompts(session) != 0) {
            return SSH_AUTH_ERROR;
        }
        err = ssh_userauth_kbdint(session, NULL, NULL);
    }

    return err;
}

int torture_rmdirs(const char *path) {
    DIR *d;
    struct dirent *dp;
    struct stat sb;
    char *fname;

    if ((d = opendir(path)) != NULL) {
        while(stat(path, &sb) == 0) {
            /* if we can remove the directory we're done */
            if (rmdir(path) == 0) {
                break;
            }
            switch (errno) {
                case ENOTEMPTY:
                case EEXIST:
                case EBADF:
                    break; /* continue */
                default:
                    closedir(d);
                    return 0;
            }

            while ((dp = readdir(d)) != NULL) {
                size_t len;
                /* skip '.' and '..' */
                if (dp->d_name[0] == '.' &&
                        (dp->d_name[1] == '\0' ||
                         (dp->d_name[1] == '.' && dp->d_name[2] == '\0'))) {
                    continue;
                }

                len = strlen(path) + strlen(dp->d_name) + 2;
                fname = malloc(len);
                if (fname == NULL) {
                    closedir(d);
                    return -1;
                }
                snprintf(fname, len, "%s/%s", path, dp->d_name);

                /* stat the file */
                if (lstat(fname, &sb) != -1) {
                    if (S_ISDIR(sb.st_mode) && !S_ISLNK(sb.st_mode)) {
                        if (rmdir(fname) < 0) { /* can't be deleted */
                            if (errno == EACCES) {
                                closedir(d);
                                SAFE_FREE(fname);
                                return -1;
                            }
                            torture_rmdirs(fname);
                        }
                    } else {
                        unlink(fname);
                    }
                } /* lstat */
                SAFE_FREE(fname);
            } /* readdir */

            rewinddir(d);
        }
    } else {
        return -1;
    }

    closedir(d);
    return 0;
}

int torture_isdir(const char *path) {
    struct stat sb;

    if (lstat (path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
        return 1;
    }

    return 0;
}

int torture_terminate_process(const char *pidfile)
{
    char buf[8] = {0};
    long int tmp;
    ssize_t rc;
    pid_t pid;
    int fd;
    int is_running = 1;
    int count;

    /* read the pidfile */
    fd = open(pidfile, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    rc = read(fd, buf, sizeof(buf));
    close(fd);
    if (rc <= 0) {
        return -1;
    }

    buf[sizeof(buf) - 1] = '\0';

    tmp = strtol(buf, NULL, 10);
    if (tmp == 0 || tmp > 0xFFFF || errno == ERANGE) {
        return -1;
    }

    pid = (pid_t)(tmp & 0xFFFF);

    for (count = 0; count < 10; count++) {
        /* Make sure the daemon goes away! */
        kill(pid, SIGTERM);

        usleep(200);

        rc = kill(pid, 0);
        if (rc != 0) {
            is_running = 0;
            break;
        }
    }

    if (is_running) {
        fprintf(stderr,
                "WARNING: The process server is still running!\n");
    }

    return 0;
}

ssh_session torture_ssh_session(const char *host,
                                const unsigned int *port,
                                const char *user,
                                const char *password) {
    ssh_session session;
    int method;
    int rc;

    if (host == NULL) {
        return NULL;
    }

    session = ssh_new();
    if (session == NULL) {
        return NULL;
    }

    if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0) {
        goto failed;
    }

    if (port != NULL) {
      if (ssh_options_set(session, SSH_OPTIONS_PORT, port) < 0) {
        goto failed;
      }
    }

    if (user != NULL) {
        if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
            goto failed;
        }
    }

    if (ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity) < 0) {
        goto failed;
    }

    if (ssh_connect(session)) {
        goto failed;
    }

    /* We are in testing mode, so consinder the hostkey as verified ;) */

    /* This request should return a SSH_REQUEST_DENIED error */
    rc = ssh_userauth_none(session, NULL);
    if (rc == SSH_ERROR) {
        goto failed;
    }
    method = ssh_userauth_list(session, NULL);
    if (method == 0) {
        goto failed;
    }

    if (password != NULL) {
        if (method & SSH_AUTH_METHOD_PASSWORD) {
            rc = ssh_userauth_password(session, NULL, password);
        } else if (method & SSH_AUTH_METHOD_INTERACTIVE) {
            rc = _torture_auth_kbdint(session, password);
        }
    } else {
        rc = ssh_userauth_publickey_auto(session, NULL, NULL);
        if (rc == SSH_AUTH_ERROR) {
            goto failed;
        }
    }
    if (rc != SSH_AUTH_SUCCESS) {
        goto failed;
    }

    return session;
failed:
    if (ssh_is_connected(session)) {
        ssh_disconnect(session);
    }
    ssh_free(session);

    return NULL;
}

#ifdef WITH_SERVER

ssh_bind torture_ssh_bind(const char *addr,
                          const unsigned int port,
                          enum ssh_keytypes_e key_type,
                          const char *private_key_file) {
    int rc;
    ssh_bind sshbind = NULL;
    enum ssh_bind_options_e opts = -1;

    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        goto out;
    }

    rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, addr);
    if (rc != 0) {
        goto out_free;
    }

    rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    if (rc != 0) {
        goto out_free;
    }

    switch (key_type) {
        case SSH_KEYTYPE_DSS:
            opts = SSH_BIND_OPTIONS_DSAKEY;
            break;
        case SSH_KEYTYPE_RSA:
            opts = SSH_BIND_OPTIONS_RSAKEY;
            break;
        case SSH_KEYTYPE_ECDSA:
            opts = SSH_BIND_OPTIONS_ECDSAKEY;
            break;
        default:
            goto out_free;
    }

    rc = ssh_bind_options_set(sshbind, opts, private_key_file);
    if (rc != 0) {
        goto out_free;
    }

    rc = ssh_bind_listen(sshbind);
    if (rc != SSH_OK) {
        goto out_free;
    }

    goto out;
 out_free:
    ssh_bind_free(sshbind);
    sshbind = NULL;
 out:
    return sshbind;
}

#endif

#ifdef WITH_SFTP

struct torture_sftp *torture_sftp_session(ssh_session session) {
    struct torture_sftp *t;
    char template[] = "/tmp/ssh_torture_XXXXXX";
    char *p;
    int rc;

    if (session == NULL) {
        return NULL;
    }

    t = malloc(sizeof(struct torture_sftp));
    if (t == NULL) {
        return NULL;
    }

    t->ssh = session;
    t->sftp = sftp_new(session);
    if (t->sftp == NULL) {
        goto failed;
    }

    rc = sftp_init(t->sftp);
    if (rc < 0) {
        goto failed;
    }

    p = mkdtemp(template);
    if (p == NULL) {
        goto failed;
    }
    /* useful if TESTUSER is not the local user */
    chmod(template,0777);
    t->testdir = strdup(p);
    if (t->testdir == NULL) {
        goto failed;
    }

    return t;
failed:
    if (t->sftp != NULL) {
        sftp_free(t->sftp);
    }
    ssh_disconnect(t->ssh);
    ssh_free(t->ssh);
	free(t);

    return NULL;
}

void torture_sftp_close(struct torture_sftp *t) {
    if (t == NULL) {
        return;
    }

    if (t->sftp != NULL) {
        sftp_free(t->sftp);
    }

    free(t->testdir);
    free(t);
}
#endif /* WITH_SFTP */

#endif /* _WIN32 */

void torture_write_file(const char *filename, const char *data){
    int fd;
    int rc;

    assert_non_null(filename);
    assert_true(filename[0] != '\0');
    assert_non_null(data);

    fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0600);
    assert_true(fd >= 0);

    rc = write(fd, data, strlen(data));
    assert_int_equal(rc, strlen(data));

    close(fd);
}

static const char *torture_get_testkey_internal(enum ssh_keytypes_e type,
                                                int bits,
                                                int with_passphrase,
                                                int pubkey)
{
    switch (type) {
    case SSH_KEYTYPE_DSS:
        if (pubkey) {
            return torture_dsa_testkey_pub;
        } else if (with_passphrase) {
            return torture_dsa_testkey_pp;
        }
        return torture_dsa_testkey;
    case SSH_KEYTYPE_RSA:
       if (pubkey) {
                return torture_rsa_testkey_pub;
       } else if (with_passphrase) {
            return torture_rsa_testkey_pp;
       }
       return torture_rsa_testkey;
    case SSH_KEYTYPE_ECDSA:
        if (bits == 521) {
            if (pubkey) {
                return torture_ecdsa521_testkey_pub;
            } else if (with_passphrase) {
		return NULL;
            }
            return torture_ecdsa521_testkey;
        } else if (bits == 384) {
            if (pubkey) {
                return torture_ecdsa384_testkey_pub;
            } else if (with_passphrase){
		return NULL;
            }
            return torture_ecdsa384_testkey;
        }

        if (pubkey) {
            return torture_ecdsa256_testkey_pub;
        } else if (with_passphrase){
		return NULL;
        }
        return torture_ecdsa256_testkey;
    case SSH_KEYTYPE_ED25519:
        if (pubkey) {
            return torture_ed25519_testkey_pub;
        } else if (with_passphrase) {
            return torture_ed25519_testkey_pp;
        }
        return torture_ed25519_testkey;
    case SSH_KEYTYPE_DSS_CERT01:
        return torture_dsa_testkey_cert;
    case SSH_KEYTYPE_RSA_CERT01:
        return torture_rsa_testkey_cert;
    case SSH_KEYTYPE_RSA1:
    case SSH_KEYTYPE_UNKNOWN:
        return NULL;
    }

    return NULL;
}

const char *torture_get_testkey(enum ssh_keytypes_e type,
                                int ecda_bits,
                                int with_passphrase)
{
    return torture_get_testkey_internal(type, ecda_bits, with_passphrase, 0);
}

const char *torture_get_testkey_pub(enum ssh_keytypes_e type, int ecda_bits)
{
    return torture_get_testkey_internal(type, ecda_bits, 0, 1);
}

const char *torture_get_testkey_passphrase(void)
{
    return TORTURE_TESTKEY_PASSWORD;
}

int torture_server_port(void)
{
    char *env = getenv("TORTURE_SERVER_PORT");

    if (env != NULL && env[0] != '\0' && strlen(env) < 6) {
        int port = atoi(env);

        if (port > 0 && port < 65536) {
            return port;
        }
    }

    return TORTURE_SSHD_SRV_PORT;
}

const char *torture_server_address(int family)
{
    switch (family) {
    case AF_INET: {
        const char *ip4 = getenv("TORTURE_SERVER_ADDRESS_IPV4");

        if (ip4 != NULL && ip4[0] != '\0') {
            return ip4;
        }

        return TORTURE_SSHD_SRV_IPV4;
    }
    case AF_INET6: {
        const char *ip6 = getenv("TORTURE_SERVER_ADDRESS_IPV6");

        if (ip6 != NULL && ip6[0] != '\0') {
            return ip6;
        }

        return TORTURE_SSHD_SRV_IPV6;
    }
    default:
        return NULL;
    }

    return NULL;
}

void torture_setup_socket_dir(void **state)
{
    struct torture_state *s;
    const char *p;
    size_t len;

    s = malloc(sizeof(struct torture_state));
    assert_non_null(s);

    s->socket_dir = strdup(TORTURE_SOCKET_DIR);
    assert_non_null(s->socket_dir);

    p = mkdtemp(s->socket_dir);
    assert_non_null(p);

    /* pcap file */
    len = strlen(p) + 1 + strlen(TORTURE_PCAP_FILE) + 1;

    s->pcap_file = malloc(len);
    assert_non_null(s->pcap_file);

    snprintf(s->pcap_file, len, "%s/%s", p, TORTURE_PCAP_FILE);

    /* pid file */
    len = strlen(p) + 1 + strlen(TORTURE_SSHD_PIDFILE) + 1;

    s->srv_pidfile = malloc(len);
    assert_non_null(s->srv_pidfile);

    snprintf(s->srv_pidfile, len, "%s/%s", p, TORTURE_SSHD_PIDFILE);

    /* config file */
    len = strlen(p) + 1 + strlen(TORTURE_SSHD_CONFIG) + 1;

    s->srv_config = malloc(len);
    assert_non_null(s->srv_config);

    snprintf(s->srv_config, len, "%s/%s", p, TORTURE_SSHD_CONFIG);

    setenv("SOCKET_WRAPPER_DIR", p, 1);
    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "170", 1);
    setenv("SOCKET_WRAPPER_PCAP_FILE", s->pcap_file, 1);

    *state = s;
}

static void torture_setup_create_sshd_config(void **state)
{
    struct torture_state *s = *state;
    char dsa_hostkey[1024];
    char rsa_hostkey[1024];
    char ecdsa_hostkey[1024];
    char trusted_ca_pubkey[1024];
    char sshd_config[2048];
    char sshd_path[1024];
    struct stat sb;
    const char *sftp_server_locations[] = {
        "/usr/lib/ssh/sftp-server",
        "/usr/libexec/sftp-server",
        "/usr/libexec/openssh/sftp-server",
        "/usr/lib/openssh/sftp-server",     /* Debian */
    };
    size_t sftp_sl_size = ARRAY_SIZE(sftp_server_locations);
    const char *sftp_server;
    size_t i;
    int rc;

    snprintf(sshd_path,
             sizeof(sshd_path),
             "%s/sshd",
             s->socket_dir);

    rc = mkdir(sshd_path, 0755);
    assert_return_code(rc, errno);

    snprintf(dsa_hostkey,
             sizeof(dsa_hostkey),
             "%s/sshd/ssh_host_dsa_key",
             s->socket_dir);
    torture_write_file(dsa_hostkey, torture_get_testkey(SSH_KEYTYPE_DSS, 0, 0));

    snprintf(rsa_hostkey,
             sizeof(rsa_hostkey),
             "%s/sshd/ssh_host_rsa_key",
             s->socket_dir);
    torture_write_file(rsa_hostkey, torture_get_testkey(SSH_KEYTYPE_RSA, 0, 0));

    snprintf(ecdsa_hostkey,
             sizeof(ecdsa_hostkey),
             "%s/sshd/ssh_host_ecdsa_key",
             s->socket_dir);
    torture_write_file(ecdsa_hostkey,
                       torture_get_testkey(SSH_KEYTYPE_ECDSA, 521, 0));

    snprintf(trusted_ca_pubkey,
             sizeof(trusted_ca_pubkey),
             "%s/sshd/user_ca.pub",
             s->socket_dir);
    torture_write_file(trusted_ca_pubkey, torture_rsa_certauth_pub);

    assert_non_null(s->socket_dir);

    sftp_server = getenv("TORTURE_SFTP_SERVER");
    if (sftp_server == NULL) {
        for (i = 0; i < sftp_sl_size; i++) {
            sftp_server = sftp_server_locations[i];
            rc = lstat(sftp_server, &sb);
            if (rc == 0) {
                break;
            }
        }
    }
    assert_non_null(sftp_server);

    snprintf(sshd_config, sizeof(sshd_config),
             "Port 22\n"
             "ListenAddress 127.0.0.10\n"
             "HostKey %s\n"
             "HostKey %s\n"
             "HostKey %s\n"
             "\n"
             "TrustedUserCAKeys %s\n"
             "\n"
             "LogLevel DEBUG3\n"
             "Subsystem sftp %s\n"
             "\n"
             "PasswordAuthentication yes\n"
             "KbdInteractiveAuthentication yes\n"
             "PubkeyAuthentication yes\n"
             "\n"
             "UsePrivilegeSeparation no\n"
             "StrictModes no\n"
             "\n"
             "UsePAM yes\n"
             "\n"
#if (OPENSSH_VERSION_MAJOR == 6 && OPENSSH_VERSION_MINOR >= 7) || (OPENSSH_VERSION_MAJOR >= 7)
             "HostKeyAlgorithms +ssh-dss\n"
             "Ciphers +3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,blowfish-cbc\n"
             "KexAlgorithms +diffie-hellman-group1-sha1"
#else
             "Ciphers 3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,"
                     "aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,"
                     "aes256-gcm@openssh.com,arcfour128,arcfour256,arcfour,"
                     "blowfish-cbc,cast128-cbc,chacha20-poly1305@openssh.com\n"
             "KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp256,"
                           "ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
                           "diffie-hellman-group-exchange-sha256,"
                           "diffie-hellman-group-exchange-sha1,"
                           "diffie-hellman-group14-sha1,"
                           "diffie-hellman-group1-sha1\n"
#endif
             "\n"
             "AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES\n"
             "AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT\n"
             "AcceptEnv LC_IDENTIFICATION LC_ALL LC_LIBSSH\n"
             "\n"
             "PidFile %s\n",
             dsa_hostkey,
             rsa_hostkey,
             ecdsa_hostkey,
             trusted_ca_pubkey,
             sftp_server,
             s->srv_pidfile);

    torture_write_file(s->srv_config, sshd_config);
}

void torture_setup_sshd_server(void **state)
{
    struct torture_state *s;
    char sshd_start_cmd[1024];
    int rc;

    torture_setup_socket_dir(state);
    torture_setup_create_sshd_config(state);

    /* Set the default interface for the server */
    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "10", 1);
    setenv("PAM_WRAPPER", "1", 1);

    s = *state;

    snprintf(sshd_start_cmd, sizeof(sshd_start_cmd),
             "/usr/sbin/sshd -r -f %s -E %s/sshd/daemon.log 2> %s/sshd/cwrap.log",
             s->srv_config, s->socket_dir, s->socket_dir);

    rc = system(sshd_start_cmd);
    assert_return_code(rc, errno);

    /* Give the process some time to start */
    usleep(500);

    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "21", 1);
    unsetenv("PAM_WRAPPER");
}

void torture_teardown_socket_dir(void **state)
{
    struct torture_state *s = *state;
    char *env = getenv("TORTURE_SKIP_CLEANUP");
    int rc;

    if (env != NULL && env[0] == '1') {
        fprintf(stderr, "[ TORTURE  ] >>> Skipping cleanup of %s\n", s->socket_dir);
    } else {
        rc = torture_rmdirs(s->socket_dir);
        if (rc < 0) {
            fprintf(stderr,
                    "torture_rmdirs(%s) failed: %s",
                    s->socket_dir,
                    strerror(errno));
        }
    }

    free(s->srv_config);
    free(s->socket_dir);
    free(s->pcap_file);
    free(s->srv_pidfile);
    free(s);
}

void torture_teardown_sshd_server(void **state)
{
    struct torture_state *s = *state;
    int rc;

    rc = torture_terminate_process(s->srv_pidfile);
    if (rc != 0) {
        fprintf(stderr, "XXXXXX Failed to terminate sshd\n");
    }

    torture_teardown_socket_dir(state);
}

int torture_libssh_verbosity(void){
  return verbosity;
}

void _torture_filter_tests(struct CMUnitTest *tests, size_t ntests)
{
    size_t i,j;
    const char *name;
    if (pattern == NULL){
        return;
    }
    for (i=0; i < ntests; ++i){
        name = tests[i].name;
        /*printf("match(%s,%s)\n",name,pattern);*/
        if (!match_pattern(name, pattern)){
            for (j = i; j < ntests-1;++j){
                tests[j]=tests[j+1];
            }
            tests[ntests-1].name = NULL;
            tests[ntests-1].test_func = NULL;
            ntests--;
            --i;
        }
    }
    if (ntests != 0){
        printf("%d tests left\n",(int)ntests);
    } else {
        printf("No matching test left\n");
    }
}

int main(int argc, char **argv) {
  struct argument_s arguments;

  arguments.verbose=0;
  arguments.pattern=NULL;
  torture_cmdline_parse(argc, argv, &arguments);
  verbosity=arguments.verbose;
  pattern=arguments.pattern;

  return torture_run_tests();
}

/* vim: set ts=4 sw=4 et cindent syntax=c.doxygen: */
