#define LIBSSH_STATIC

#include "torture.h"
#include "pki.c"
#include <sys/stat.h>
#include <fcntl.h>

#define LIBSSH_RSA_TESTKEY "libssh_testkey.id_rsa"
#define LIBSSH_DSA_TESTKEY "libssh_testkey.id_dsa"
#define LIBSSH_ECDSA_TESTKEY "libssh_testkey.id_ecdsa"
#define LIBSSH_PASSPHRASE "libssh-rocks"
const unsigned char HASH[] = "12345678901234567890";

static const char rsa_testkey[]=
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
static const char rsa_testkey_pub[]=
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsA5ERRaUFckApnmEAFjLGdFrIN"
        "k/Vsl4ts9Ur6enF6auEfJmCN1tjcAOi34lHJaO+WXbDYYj7duW3SP7H9lbCMwq79B"
        "hzJxinkcvTWCjE7G66xluL4qIdEYHrPQQx1cztTzZTuUD+P/8fJmmnIONQOeJZptd"
        "AmB7ySwZcZOIV4An/rzu5X4klyMY/EAYVDHPKOK1/8Wsv1LRYYplvKp4YPPJ4FnU0"
        "si5qI45HIsZJbh24csM3vwSawmfCqDaAlCZFJoPgE1kyO1t+IVxIv1TDhdAVOxa6B"
        "QMRjUBThzmDXWeHMfMGL2ow63kPOtlCkPiPSADYs4ekeGg52DVm4esZ "
        "aris@aris-air\n";

static const char dsa_testkey[]=
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
static const char dsa_testkey_pub[]=
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

static const char rsa_testkey_pp[]=
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

static const char dsa_testkey_pp[]=
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

static const char ecdsa256_testkey[]=
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEIBCDeeYYAtX3EnsP0ratwVpNTaA/4K1N6VvHMiUZlVdhoAoGCCqGSM49\n"
        "AwEHoUQDQgAEx+9ud88Q5GWtLd+yMtYaapC85g+2ZLp7VtFHA0EbNHqBUQxoh+Ik\n"
        "89Mlr7AUxcFPd+kCo+NE6yq/mNQcL7E6iQ==\n"
        "-----END EC PRIVATE KEY-----\n";
static const char ecdsa256_testkey_pub[]=
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNT"
        "YAAABBBMfvbnfPEORlrS3fsjLWGmqQvOYPtmS6e1bRRwNBGzR6gVEMaIfiJPPTJa+w"
        "FMXBT3fpAqPjROsqv5jUHC+xOok= aris@kalix86\n";
static const char ecdsa384_testkey[]=
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MIGkAgEBBDBY8jEa5DtRy4AVeTWhPJ/TK257behiC3uafEi6YA2oHORibqX55EDN\n"
        "wz29MT40mQSgBwYFK4EEACKhZANiAARXc4BN6BrVo1QMi3+i/B85Lu7SMuzBi+1P\n"
        "bJti8xz+Szgq64gaBGOK9o+WOdLAd/w7p7DJLdztJ0bYoyT4V3B3ZqR9RyGq6mYC\n"
        "jkXlc5YbYHjueBbp0oeNXqsXHNAWQZo=\n"
        "-----END EC PRIVATE KEY-----\n";
static const char ecdsa384_testkey_pub[]=
        "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzOD"
        "QAAABhBFdzgE3oGtWjVAyLf6L8Hzku7tIy7MGL7U9sm2LzHP5LOCrriBoEY4r2j5Y5"
        "0sB3/DunsMkt3O0nRtijJPhXcHdmpH1HIarqZgKOReVzlhtgeO54FunSh41eqxcc0B"
        "ZBmg== aris@kalix86";
static const char ecdsa521_testkey[]=
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MIHbAgEBBEG83nSJ2SLoiBvEku1JteQKWx/Xt6THksgC7rrIaTUmNzk+60f0sCCm\n"
        "Gll0dgrZLmeIw+TtnG1E20VZflCKq+IdkaAHBgUrgQQAI6GBiQOBhgAEAc6D728d\n"
        "baQkHnSPtztaRwJw63CBl15cykB4SXXuwWdNOtPzBijUULMTTvBXbra8gL4ATd9d\n"
        "Qnuwn8KQUh2T/z+BARjWPKhcHcGx57XpXCEkawzMYaHUUnRdeFEmNRsbXypsf0mJ\n"
        "KATU3h8gzTMkbrx8DJTFHEIjXBShs44HsSYVl3Xy\n"
        "-----END EC PRIVATE KEY-----\n";
static const char ecdsa521_testkey_pub[]=
        "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1Mj"
        "EAAACFBAHOg+9vHW2kJB50j7c7WkcCcOtwgZdeXMpAeEl17sFnTTrT8wYo1FCzE07w"
        "V262vIC+AE3fXUJ7sJ/CkFIdk/8/gQEY1jyoXB3Bsee16VwhJGsMzGGh1FJ0XXhRJj"
        "UbG18qbH9JiSgE1N4fIM0zJG68fAyUxRxCI1wUobOOB7EmFZd18g== aris@kalix86";

static void write_file(const char *filename, const char *data);
static void setup_rsa_key(void **state) {
    (void) state; /* unused */

    unlink(LIBSSH_RSA_TESTKEY);
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    write_file(LIBSSH_RSA_TESTKEY, rsa_testkey);
    write_file(LIBSSH_RSA_TESTKEY ".pub", rsa_testkey_pub);
}

static void setup_dsa_key(void **state) {
    (void) state; /* unused */

    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    write_file(LIBSSH_DSA_TESTKEY, dsa_testkey);
    write_file(LIBSSH_DSA_TESTKEY ".pub", dsa_testkey_pub);
}

#ifdef HAVE_OPENSSL_ECC
static void setup_ecdsa_key(void **state, int ecdsa_bits) {

    (void) state; /* unused */

    unlink(LIBSSH_ECDSA_TESTKEY);
    unlink(LIBSSH_ECDSA_TESTKEY ".pub");

    if (ecdsa_bits == 256) {
        write_file(LIBSSH_ECDSA_TESTKEY, ecdsa256_testkey);
        write_file(LIBSSH_ECDSA_TESTKEY ".pub", ecdsa256_testkey_pub);
    } else if (ecdsa_bits == 384) {
        write_file(LIBSSH_ECDSA_TESTKEY, ecdsa384_testkey);
        write_file(LIBSSH_ECDSA_TESTKEY ".pub", ecdsa384_testkey_pub);
    } else if (ecdsa_bits == 521) {
        write_file(LIBSSH_ECDSA_TESTKEY, ecdsa521_testkey);
        write_file(LIBSSH_ECDSA_TESTKEY ".pub", ecdsa521_testkey_pub);
    }
}

static void setup_ecdsa_key_521(void **state) {
    setup_ecdsa_key(state, 521);
}

static void setup_ecdsa_key_384(void **state) {
    setup_ecdsa_key(state, 384);
}

static void setup_ecdsa_key_256(void **state) {
    setup_ecdsa_key(state, 256);
}
#endif

static void setup_both_keys(void **state) {
    (void) state; /* unused */

    setup_rsa_key(state);
    setup_dsa_key(state);
}

static void teardown(void **state) {
    (void) state; /* unused */

    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    unlink(LIBSSH_RSA_TESTKEY);
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    unlink(LIBSSH_ECDSA_TESTKEY);
    unlink(LIBSSH_ECDSA_TESTKEY ".pub");
}

static char *read_file(const char *filename) {
    char *key;
    int fd;
    int size;
    int rc;
    struct stat sb;

    assert_true(filename != NULL);
    assert_true(*filename != '\0');

    fd = open(filename, O_RDONLY);
    assert_true(fd >= 0);

    rc = fstat(fd, &sb);
    assert_int_equal(rc, 0);

    key = malloc(sb.st_size + 1);
    assert_true(key != NULL);

    size = read(fd, key, sb.st_size);
    assert_true(size == sb.st_size);

    close(fd);

    key[size] = '\0';
    return key;
}

static void write_file(const char *filename, const char *data){
    int fd;
    int rc;

    assert_non_null(filename);
    assert_true(filename[0] != '\0');
    assert_non_null(data);

    fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0755);
    assert_true(fd >= 0);

    rc = write(fd, data, strlen(data));
    assert_int_equal(rc, strlen(data));

    close(fd);
}

static int torture_read_one_line(const char *filename, char *buffer, size_t len) {
  FILE *fp;
  size_t rc;

  fp = fopen(filename, "r");
  if (fp == NULL) {
    return -1;
  }

  rc = fread(buffer, len, 1, fp);
  if (rc != 0 || ferror(fp)) {
    fclose(fp);
    return -1;
  }

  fclose(fp);

  return 0;
}

/** @internal
 * returns the character len of a public key string, omitting the comment part
 */
static int torture_pubkey_len(const char *pubkey){
    const char *ptr;
    ptr=strchr(pubkey, ' ');
    if (ptr != NULL){
        ptr = strchr(ptr + 1, ' ');
        if (ptr != NULL){
            return ptr - pubkey;
        }
    }
    return 0;
}

static void torture_pki_keytype(void **state) {
    enum ssh_keytypes_e type;
    const char *type_c;

    (void) state; /* unused */

    type = ssh_key_type(NULL);
    assert_true(type == SSH_KEYTYPE_UNKNOWN);

    type = ssh_key_type_from_name(NULL);
    assert_true(type == SSH_KEYTYPE_UNKNOWN);

    type = ssh_key_type_from_name("42");
    assert_true(type == SSH_KEYTYPE_UNKNOWN);

    type_c = ssh_key_type_to_char(SSH_KEYTYPE_UNKNOWN);
    assert_true(type_c == NULL);

    type_c = ssh_key_type_to_char(42);
    assert_true(type_c == NULL);
}

static void torture_pki_signature(void **state)
{
    ssh_signature sig;

    (void) state; /* unused */

    sig = ssh_signature_new();
    assert_true(sig != NULL);

    ssh_signature_free(sig);
}

static void torture_pki_import_privkey_base64_RSA(void **state) {
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = LIBSSH_PASSPHRASE;
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    key_str = read_file(LIBSSH_RSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_RSA);

    rc = ssh_key_is_public(key);
    assert_true(rc == 1);

    free(key_str);
    ssh_key_free(key);
}

static void torture_pki_import_privkey_base64_NULL_key(void **state) {
    int rc;
    const char *passphrase = LIBSSH_PASSPHRASE;

    (void) state; /* unused */

    /* test if it returns -1 if key is NULL */
    rc = ssh_pki_import_privkey_base64(rsa_testkey, passphrase, NULL, NULL, NULL);
    assert_true(rc == -1);

}

static void torture_pki_import_privkey_base64_NULL_str(void **state) {
    int rc;
    ssh_key key = NULL;
    const char *passphrase = LIBSSH_PASSPHRASE;

    (void) state; /* unused */

    /* test if it returns -1 if key_str is NULL */
    rc = ssh_pki_import_privkey_base64(NULL, passphrase, NULL, NULL, &key);
    assert_true(rc == -1);

    ssh_key_free(key);
}

static void torture_pki_import_privkey_base64_DSA(void **state) {
    int rc;
    ssh_key key;
    const char *passphrase = LIBSSH_PASSPHRASE;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(dsa_testkey, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    ssh_key_free(key);
}

#ifdef HAVE_ECC
static void torture_pki_import_privkey_base64_ECDSA(void **state) {
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = LIBSSH_PASSPHRASE;

    (void) state; /* unused */

    key_str = read_file(LIBSSH_ECDSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    free(key_str);
    ssh_key_free(key);
}
#endif

static void torture_pki_import_privkey_base64_passphrase(void **state) {
    int rc;
    ssh_key key = NULL;
    const char *passphrase = LIBSSH_PASSPHRASE;

    (void) state; /* unused */


    rc = ssh_pki_import_privkey_base64(rsa_testkey_pp, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);
    ssh_key_free(key);

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(rsa_testkey_pp, "wrong passphrase !!", NULL,
            NULL, &key);
    assert_true(rc == -1);

#ifndef HAVE_LIBCRYPTO
    /* test if it returns -1 if passphrase is NULL */
    /* libcrypto asks for a passphrase, so skip this test */
    rc = ssh_pki_import_privkey_base64(rsa_testkey_pp, NULL, NULL, NULL, &key);
    assert_true(rc == -1);
#endif

    /* same for DSA */

    rc = ssh_pki_import_privkey_base64(dsa_testkey_pp, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);
    ssh_key_free(key);

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(dsa_testkey_pp, "wrong passphrase !!", NULL, NULL, &key);
    assert_true(rc == -1);

#ifndef HAVE_LIBCRYPTO
    /* test if it returns -1 if passphrase is NULL */
    /* libcrypto asks for a passphrase, so skip this test */
    rc = ssh_pki_import_privkey_base64(dsa_testkey_pp, NULL, NULL, NULL, &key);
    assert_true(rc == -1);
#endif

}

static void torture_pki_pki_publickey_from_privatekey_RSA(void **state) {
    int rc;
    ssh_key key;
    ssh_key pubkey;
    const char *passphrase = NULL;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(rsa_testkey, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_true(rc == SSH_OK);

    ssh_key_free(key);
    ssh_key_free(pubkey);
}

static void torture_pki_pki_publickey_from_privatekey_DSA(void **state) {
    int rc;
    ssh_key key;
    ssh_key pubkey;
    const char *passphrase = NULL;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(dsa_testkey, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_true(rc == SSH_OK);

    ssh_key_free(key);
    ssh_key_free(pubkey);
}

#ifdef HAVE_ECC
static void torture_pki_publickey_from_privatekey_ECDSA(void **state) {
    int rc;
    char *key_str;
    ssh_key key;
    ssh_key pubkey;
    const char *passphrase = NULL;

    (void) state; /* unused */

    key_str = read_file(LIBSSH_ECDSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_true(rc == SSH_OK);

    free(key_str);
    ssh_key_free(key);
    ssh_key_free(pubkey);
}
#endif

static void torture_pki_publickey_dsa_base64(void **state)
{
    enum ssh_keytypes_e type;
    char *b64_key, *key_buf, *p;
    const char *q;
    ssh_key key;
    int rc;

    (void) state; /* unused */

    key_buf = strdup(dsa_testkey_pub);
    assert_true(key_buf != NULL);

    q = p = key_buf;
    while (*p != ' ') p++;
    *p = '\0';

    type = ssh_key_type_from_name(q);
    assert_true(type == SSH_KEYTYPE_DSS);

    q = ++p;
    while (*p != ' ') p++;
    *p = '\0';

    rc = ssh_pki_import_pubkey_base64(q, type, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    assert_true(rc == 0);

    assert_string_equal(q, b64_key);

    free(b64_key);
    free(key_buf);
    ssh_key_free(key);
}

#ifdef HAVE_ECC
static void torture_pki_publickey_ecdsa_base64(void **state)
{
    enum ssh_keytypes_e type;
    char *b64_key, *key_buf, *p;
    const char *q;
    ssh_key key;
    int rc;

    (void) state; /* unused */

    key_buf = read_file(LIBSSH_ECDSA_TESTKEY ".pub");
    assert_true(key_buf != NULL);

    q = p = key_buf;
    while (*p != ' ') p++;
    *p = '\0';

    type = ssh_key_type_from_name(q);
    assert_true(type == SSH_KEYTYPE_ECDSA);

    q = ++p;
    while (*p != ' ') p++;
    *p = '\0';

    rc = ssh_pki_import_pubkey_base64(q, type, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    assert_true(rc == 0);

    assert_string_equal(q, b64_key);

    free(b64_key);
    free(key_buf);
    ssh_key_free(key);
}
#endif

static void torture_pki_publickey_rsa_base64(void **state)
{
    enum ssh_keytypes_e type;
    char *b64_key, *key_buf, *p;
    const char *q;
    ssh_key key;
    int rc;

    (void) state; /* unused */

    key_buf = strdup(rsa_testkey_pub);
    assert_true(key_buf != NULL);

    q = p = key_buf;
    while (*p != ' ') p++;
    *p = '\0';

    type = ssh_key_type_from_name(q);
    assert_true(((type == SSH_KEYTYPE_RSA) ||
                 (type == SSH_KEYTYPE_RSA1)));

    q = ++p;
    while (*p != ' ') p++;
    *p = '\0';

    rc = ssh_pki_import_pubkey_base64(q, type, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    assert_true(rc == 0);

    assert_string_equal(q, b64_key);

    free(b64_key);
    free(key_buf);
    ssh_key_free(key);
}

static void torture_generate_pubkey_from_privkey_rsa(void **state) {
    char pubkey_generated[4096] = {0};
    ssh_key privkey;
    ssh_key pubkey;
    int rc;
    int len;

    (void) state; /* unused */

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_RSA_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_RSA_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);

    len = torture_pubkey_len(rsa_testkey_pub);
    assert_int_equal(strncmp(rsa_testkey_pub, pubkey_generated, len), 0);

    ssh_key_free(privkey);
    ssh_key_free(pubkey);
}

static void torture_generate_pubkey_from_privkey_dsa(void **state) {
    char pubkey_generated[4096] = {0};
    ssh_key privkey;
    ssh_key pubkey;
    int len;
    int rc;

    (void) state; /* unused */

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_DSA_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_DSA_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);
    len = torture_pubkey_len(dsa_testkey_pub);
    assert_int_equal(strncmp(dsa_testkey_pub, pubkey_generated, len), 0);

    ssh_key_free(privkey);
    ssh_key_free(pubkey);
}

#ifdef HAVE_ECC
static void torture_generate_pubkey_from_privkey_ecdsa(void **state) {
    char pubkey_original[4096] = {0};
    char pubkey_generated[4096] = {0};
    ssh_key privkey;
    ssh_key pubkey;
    int rc;
    int len;

    (void) state; /* unused */

    rc = torture_read_one_line(LIBSSH_ECDSA_TESTKEY ".pub",
                               pubkey_original,
                               sizeof(pubkey_original));
    assert_true(rc == 0);

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_ECDSA_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_ECDSA_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_ECDSA_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);
    len = torture_pubkey_len(pubkey_original);
    assert_int_equal(strncmp(pubkey_original, pubkey_generated, len), 0);

    ssh_key_free(privkey);
    ssh_key_free(pubkey);
}
#endif

static void torture_pki_duplicate_key_rsa(void **state)
{
    int rc;
    char *b64_key;
    char *b64_key_gen;
    ssh_key pubkey;
    ssh_key privkey;
    ssh_key privkey_dup;

    (void) state;

    rc = ssh_pki_import_pubkey_file(LIBSSH_RSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key);
    assert_true(rc == 0);
    ssh_key_free(pubkey);

    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    privkey_dup = ssh_key_dup(privkey);
    assert_true(privkey_dup != NULL);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key_gen);
    assert_true(rc == 0);

    assert_string_equal(b64_key, b64_key_gen);

    rc = ssh_key_cmp(privkey, privkey_dup, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(pubkey);
    ssh_key_free(privkey);
    ssh_key_free(privkey_dup);
    ssh_string_free_char(b64_key);
    ssh_string_free_char(b64_key_gen);
}

static void torture_pki_duplicate_key_dsa(void **state)
{
    int rc;
    char *b64_key;
    char *b64_key_gen;
    ssh_key pubkey;
    ssh_key privkey;
    ssh_key privkey_dup;

    (void) state;

    rc = ssh_pki_import_pubkey_file(LIBSSH_DSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key);
    assert_true(rc == 0);
    ssh_key_free(pubkey);

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    privkey_dup = ssh_key_dup(privkey);
    assert_true(privkey_dup != NULL);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key_gen);
    assert_true(rc == 0);

    assert_string_equal(b64_key, b64_key_gen);

    rc = ssh_key_cmp(privkey, privkey_dup, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(pubkey);
    ssh_key_free(privkey);
    ssh_key_free(privkey_dup);
    ssh_string_free_char(b64_key);
    ssh_string_free_char(b64_key_gen);
}

#ifdef HAVE_ECC
static void torture_pki_duplicate_key_ecdsa(void **state)
{
    int rc;
    char *b64_key;
    char *b64_key_gen;
    ssh_key pubkey;
    ssh_key privkey;
    ssh_key privkey_dup;

    (void) state;

    rc = ssh_pki_import_pubkey_file(LIBSSH_ECDSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key);
    assert_true(rc == 0);
    ssh_key_free(pubkey);

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    privkey_dup = ssh_key_dup(privkey);
    assert_true(privkey_dup != NULL);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key_gen);
    assert_true(rc == 0);

    assert_string_equal(b64_key, b64_key_gen);

    rc = ssh_key_cmp(privkey, privkey_dup, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(pubkey);
    ssh_key_free(privkey);
    ssh_key_free(privkey_dup);
    ssh_string_free_char(b64_key);
    ssh_string_free_char(b64_key_gen);
}

/* Test case for bug #147: Private ECDSA key duplication did not carry
 * over parts of the key that then caused subsequent key demotion to
 * fail.
 */
static void torture_pki_ecdsa_duplicate_then_demote(void **state)
{
    ssh_key pubkey;
    ssh_key privkey;
    ssh_key privkey_dup;
    int rc;

    (void) state;

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    privkey_dup = ssh_key_dup(privkey);
    assert_true(privkey_dup != NULL);
    assert_int_equal(privkey->ecdsa_nid, privkey_dup->ecdsa_nid);

    rc = ssh_pki_export_privkey_to_pubkey(privkey_dup, &pubkey);
    assert_true(rc == 0);
    assert_int_equal(pubkey->ecdsa_nid, privkey->ecdsa_nid);

    ssh_key_free(pubkey);
    ssh_key_free(privkey);
    ssh_key_free(privkey_dup);
}
#endif

static void torture_pki_generate_key_rsa(void **state)
{
    int rc;
    ssh_key key;
    ssh_signature sign;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 1024, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 2048, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 4096, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}

static void torture_pki_generate_key_rsa1(void **state)
{
    int rc;
    ssh_key key;
    ssh_signature sign;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA1, 1024, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA1, 2048, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA1, 4096, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}

static void torture_pki_generate_key_dsa(void **state)
{
    int rc;
    ssh_key key;
    ssh_signature sign;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 1024, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 2048, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 3072, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}

#ifdef HAVE_ECC
static void torture_pki_generate_key_ecdsa(void **state)
{
    int rc;
    ssh_key key;
    ssh_signature sign;
    enum ssh_keytypes_e type = SSH_KEYTYPE_UNKNOWN;
    const char *type_char = NULL;
    const char *etype_char = NULL;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_ECDSA, 256, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ECDSA);
    type_char = ssh_key_type_to_char(type);
    assert_true(strcmp(type_char, "ssh-ecdsa") == 0);
    etype_char = ssh_pki_key_ecdsa_name(key);
    assert_true(strcmp(etype_char, "ecdsa-sha2-nistp256") == 0);

    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_ECDSA, 384, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ECDSA);
    type_char = ssh_key_type_to_char(type);
    assert_true(strcmp(type_char, "ssh-ecdsa") == 0);
    etype_char =ssh_pki_key_ecdsa_name(key);
    assert_true(strcmp(etype_char, "ecdsa-sha2-nistp384") == 0);

    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_ECDSA, 512, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ECDSA);
    type_char = ssh_key_type_to_char(type);
    assert_true(strcmp(type_char, "ssh-ecdsa") == 0);
    etype_char =ssh_pki_key_ecdsa_name(key);
    assert_true(strcmp(etype_char, "ecdsa-sha2-nistp521") == 0);

    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}
#endif

#ifdef HAVE_LIBCRYPTO
static void torture_pki_write_privkey_rsa(void **state)
{
    ssh_key origkey;
    ssh_key privkey;
    int rc;

    (void) state; /* unused */

    ssh_set_log_level(5);

    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);

    unlink(LIBSSH_RSA_TESTKEY);

    rc = ssh_pki_export_privkey_file(origkey,
                                     "",
                                     NULL,
                                     NULL,
                                     LIBSSH_RSA_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(origkey);
    ssh_key_free(privkey);
}

static void torture_pki_write_privkey_dsa(void **state)
{
    ssh_key origkey;
    ssh_key privkey;
    int rc;

    (void) state; /* unused */

    ssh_set_log_level(5);

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);

    unlink(LIBSSH_DSA_TESTKEY);

    rc = ssh_pki_export_privkey_file(origkey,
                                     "",
                                     NULL,
                                     NULL,
                                     LIBSSH_DSA_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(origkey);
    ssh_key_free(privkey);
}

#ifdef HAVE_ECC
static void torture_pki_write_privkey_ecdsa(void **state)
{
    ssh_key origkey;
    ssh_key privkey;
    int rc;

    (void) state; /* unused */

    ssh_set_log_level(5);

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);

    unlink(LIBSSH_ECDSA_TESTKEY);

    rc = ssh_pki_export_privkey_file(origkey,
                                     "",
                                     NULL,
                                     NULL,
                                     LIBSSH_ECDSA_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(origkey);
    ssh_key_free(privkey);
}
#endif
#endif /* HAVE_LIBCRYPTO */

#ifdef HAVE_ECC
static void torture_pki_ecdsa_name(void **state, const char *expected_name)
{
    int rc;
    ssh_key key;
    const char *etype_char = NULL;

    (void) state; /* unused */

    ssh_set_log_level(5);

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY, NULL, NULL, NULL, &key);
    assert_true(rc == 0);

    etype_char =ssh_pki_key_ecdsa_name(key);
    assert_true(strcmp(etype_char, expected_name) == 0);

    ssh_key_free(key);
}

static void torture_pki_ecdsa_name256(void **state)
{
    torture_pki_ecdsa_name(state, "ecdsa-sha2-nistp256");
}

static void torture_pki_ecdsa_name384(void **state)
{
    torture_pki_ecdsa_name(state, "ecdsa-sha2-nistp384");
}

static void torture_pki_ecdsa_name521(void **state)
{
    torture_pki_ecdsa_name(state, "ecdsa-sha2-nistp521");
}
#endif

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test(torture_pki_keytype),

        unit_test(torture_pki_signature),

        /* ssh_pki_import_privkey_base64 */
        unit_test_setup_teardown(torture_pki_import_privkey_base64_NULL_key,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_import_privkey_base64_NULL_str,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_import_privkey_base64_RSA,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_import_privkey_base64_DSA,
                                 setup_dsa_key,
                                 teardown),
#ifdef HAVE_ECC
        unit_test_setup_teardown(torture_pki_import_privkey_base64_ECDSA,
                                 setup_ecdsa_key_256,
                                 teardown),
        unit_test_setup_teardown(torture_pki_import_privkey_base64_ECDSA,
                                 setup_ecdsa_key_384,
                                 teardown),
        unit_test_setup_teardown(torture_pki_import_privkey_base64_ECDSA,
                                 setup_ecdsa_key_521,
                                 teardown),
#endif
        unit_test(torture_pki_import_privkey_base64_passphrase),
        /* ssh_pki_export_privkey_to_pubkey */
        unit_test_setup_teardown(torture_pki_pki_publickey_from_privatekey_RSA,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_pki_publickey_from_privatekey_DSA,
                                 setup_dsa_key,
                                 teardown),
#ifdef HAVE_ECC
        unit_test_setup_teardown(torture_pki_publickey_from_privatekey_ECDSA,
                                 setup_ecdsa_key_256,
                                 teardown),
        unit_test_setup_teardown(torture_pki_publickey_from_privatekey_ECDSA,
                                 setup_ecdsa_key_384,
                                 teardown),
        unit_test_setup_teardown(torture_pki_publickey_from_privatekey_ECDSA,
                                 setup_ecdsa_key_521,
                                 teardown),
        unit_test_setup_teardown(torture_pki_ecdsa_duplicate_then_demote,
                                 setup_ecdsa_key_256,
                                 teardown),
        unit_test_setup_teardown(torture_pki_ecdsa_duplicate_then_demote,
                                 setup_ecdsa_key_384,
                                 teardown),
        unit_test_setup_teardown(torture_pki_ecdsa_duplicate_then_demote,
                                 setup_ecdsa_key_521,
                                 teardown),
#endif
        /* public key */
        unit_test_setup_teardown(torture_pki_publickey_dsa_base64,
                                 setup_dsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_publickey_rsa_base64,
                                 setup_rsa_key,
                                 teardown),
#ifdef HAVE_ECC
        unit_test_setup_teardown(torture_pki_publickey_ecdsa_base64,
                                 setup_ecdsa_key_256,
                                 teardown),
        unit_test_setup_teardown(torture_pki_publickey_ecdsa_base64,
                                 setup_ecdsa_key_384,
                                 teardown),
        unit_test_setup_teardown(torture_pki_publickey_ecdsa_base64,
                                 setup_ecdsa_key_521,
                                 teardown),
#endif

        unit_test_setup_teardown(torture_generate_pubkey_from_privkey_dsa,
                                 setup_dsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_generate_pubkey_from_privkey_rsa,
                                 setup_rsa_key,
                                 teardown),
#ifdef HAVE_ECC
        unit_test_setup_teardown(torture_generate_pubkey_from_privkey_ecdsa,
                                 setup_ecdsa_key_256,
                                 teardown),
        unit_test_setup_teardown(torture_generate_pubkey_from_privkey_ecdsa,
                                 setup_ecdsa_key_384,
                                 teardown),
        unit_test_setup_teardown(torture_generate_pubkey_from_privkey_ecdsa,
                                 setup_ecdsa_key_521,
                                 teardown),
#endif

        unit_test_setup_teardown(torture_pki_duplicate_key_rsa,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_duplicate_key_dsa,
                                 setup_dsa_key,
                                 teardown),
#ifdef HAVE_ECC
        unit_test_setup_teardown(torture_pki_duplicate_key_ecdsa,
                                 setup_ecdsa_key_256,
                                 teardown),
        unit_test_setup_teardown(torture_pki_duplicate_key_ecdsa,
                                 setup_ecdsa_key_384,
                                 teardown),
        unit_test_setup_teardown(torture_pki_duplicate_key_ecdsa,
                                 setup_ecdsa_key_521,
                                 teardown),
#endif
        unit_test(torture_pki_generate_key_rsa),
        unit_test(torture_pki_generate_key_rsa1),
        unit_test(torture_pki_generate_key_dsa),
#ifdef HAVE_ECC
        unit_test(torture_pki_generate_key_ecdsa),
#endif
#ifdef HAVE_LIBCRYPTO
        unit_test_setup_teardown(torture_pki_write_privkey_rsa,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_write_privkey_dsa,
                                 setup_dsa_key,
                                 teardown),
#ifdef HAVE_ECC
        unit_test_setup_teardown(torture_pki_write_privkey_ecdsa,
                                 setup_ecdsa_key_256,
                                 teardown),
        unit_test_setup_teardown(torture_pki_write_privkey_ecdsa,
                                 setup_ecdsa_key_384,
                                 teardown),
        unit_test_setup_teardown(torture_pki_write_privkey_ecdsa,
                                 setup_ecdsa_key_521,
                                 teardown),
#endif
#endif /* HAVE_LIBCRYPTO */
#ifdef HAVE_ECC
        unit_test_setup_teardown(torture_pki_ecdsa_name256,
                                 setup_ecdsa_key_256,
                                 teardown),
        unit_test_setup_teardown(torture_pki_ecdsa_name384,
                                 setup_ecdsa_key_384,
                                 teardown),
        unit_test_setup_teardown(torture_pki_ecdsa_name521,
                                 setup_ecdsa_key_521,
                                 teardown),
#endif
    };

    (void)setup_both_keys;

    ssh_init();
    rc=run_tests(tests);
    ssh_finalize();
    return rc;
}
