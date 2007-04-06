#include <stdio.h>
#include <string.h>
#include "../md5.h"

struct testcase {
    unsigned char key[2048];
    int klen;
    unsigned char data[2048];
    int dlen;
    unsigned char mac[MD5_DIGEST_SZ];
};

int main()
{
    struct testcase test[7];
    int t = 0;

    /* test_case =     1
       key =           0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
       key_len =       16
       data =          "
       data_len =      8
       digest =        0x9294727a3638bb1c13f48ef8158bfc9d */

    memset(test[t].key, 0x0b, test[t].klen = 16);
    memcpy(test[t].data, "Hi There", test[t].dlen = 8);
    memcpy(test[t++].mac, "\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d", 16);

    /* test_case =     2
       key =           "Jefe"
       key_len =       4
       data =          "what do ya want for nothing?"
       data_len =      28
       digest =        0x750c783e6ab0b503eaa86e310a5db738 */

    memcpy(test[t].key, "Jefe", test[t].klen = 4);
    memcpy(test[t].data, "what do ya want for nothing?", test[t].dlen = 28);
    memcpy(test[t++].mac, "\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38", 16);

    /* test_case =     3
       key =           0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
       key_len         16
       data =          0xdd repeated 50 times
       data_len =      50
       digest =        0x56be34521d144c88dbb8c733f0e8b3f6 */

    memset(test[t].key, 0xaa, test[t].klen = 16);
    memset(test[t].data, 0xdd, test[t].dlen = 50);
    memcpy(test[t++].mac, "\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6", 16);

    /* test_case =     4
       key =           0x0102030405060708090a0b0c0d0e0f10111213141516171819
       key_len         25
       data =          0xcd repeated 50 times
       data_len =      50
       digest =        0x697eaf0aca3a3aea3a75164746ffaa79 */

    memcpy(test[t].key, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", test[t].klen = 25);
    memset(test[t].data, 0xcd, test[t].dlen = 50);
    memcpy(test[t++].mac, "\x69\x7e\xaf\x0a\xca\x3a\x3a\xea\x3a\x75\x16\x47\x46\xff\xaa\x79", 16);

    /* test_case =     5
       key =           0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
       key_len =       16
       data =          "Test With Truncation"
       data_len =      20
       digest =        0x56461ef2342edc00f9bab995690efd4c
       digest-96       0x56461ef2342edc00f9bab995 */

    memset(test[t].key, 0x0c, test[t].klen = 16);
    memcpy(test[t].data, "Test With Truncation", test[t].dlen = 20);
    memcpy(test[t++].mac, "\x56\x46\x1e\xf2\x34\x2e\xdc\x00\xf9\xba\xb9\x95\x69\x0e\xfd\x4c", 16);

    /* test_case =     6
       key =           0xaa repeated 80 times
       key_len =       80
       data =          "Test Using Larger Than Block-Size Key - Hash Key First"
       data_len =      54
       digest =        0x6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd */

    memset(test[t].key, 0xaa, test[t].klen = 80);
    memcpy(test[t].data, "Test Using Larger Than Block-Size Key - Hash Key First", test[t].dlen = 54);
    memcpy(test[t++].mac, "\x6b\x1a\xb7\xfe\x4b\xd7\xbf\x8f\x0b\x62\xe6\xce\x61\xb9\xd0\xcd", 16);

    /* test_case =     7
       key =           0xaa repeated 80 times
       key_len =       80
       data =          "Test Using Larger Than Block-Size Key and Larger
			Than One Block-Size Data"
       data_len =      73
       digest =        0x6f630fad67cda0ee1fb1f562db3aa53e */

    memset(test[t].key, 0xaa, test[t].klen = 80);
    memcpy(test[t].data, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", test[t].dlen = 73);
    memcpy(test[t++].mac, "\x6f\x63\x0f\xad\x67\xcd\xa0\xee\x1f\xb1\xf5\x62\xdb\x3a\xa5\x3e", 16);

    for (t = 0; t < 7; t++)
    {
	unsigned char mac[MD5_DIGEST_SZ];
	MD5_HMAC(mac, test[t].key, test[t].klen, test[t].data, test[t].dlen);
	printf("test %d %s: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	    t + 1, memcmp(mac, test[t].mac, MD5_DIGEST_SZ) ? "FAIL" : "PASS",
	    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6], mac[7],
	    mac[8], mac[9], mac[10], mac[11], mac[12], mac[13], mac[14], mac[15]);
    }

    return 0;
}
