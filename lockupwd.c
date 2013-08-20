#include <stdio.h>
#include <string.h>

void main(int argc,char *argv[])
{
    FILE *f;
    unsigned char *buf, *pass, xorValue;
    size_t  i, j, len;

    puts("OS/2 PM Lockup Password Recovery");
    if(argc != 2) puts("Usage: lockupwd [[drive:]\\path\\]os2.ini");
    else
    {
        printf("Processing %s... ",argv[1]);
        f = fopen(argv[1], "rb");
        if (!f) puts("unable to open!");
        else
        {
            fseek(f, 0, SEEK_END);
            len = ftell(f);
            fseek(f, 0, SEEK_SET);
    
            buf = (unsigned char *)malloc(len + 128);
            if (!buf) printf("not enough memory!\n");
            else
            {
                if (fread(buf, 1, len, f) != len) puts("read error!");
                else
                {
                    for (i = 0; i < len; i++)
                    {
                        if (!memcmp(&buf[i],      "PM_Lockup", 10) &&
                            !memcmp(&buf[i + 34], "LockupOptions", 14))
                        {
                            i += 54;
                            break;
                        }
                    }
                    puts("done!");
                    if (i >= len) puts("No lockup info found!");
                    else
                    {
                        xorValue = (*(unsigned short*)&buf[i] - 0x24)/3;
                        pass = &buf[i+=4];

                        do { buf[i++] ^= xorValue; } while(buf[i]);

                        printf("Password (text): \"%s\"\n",pass);

                        printf("Password (hex):");
                        do { printf(" %02X", *pass++); } while(*pass);
                        puts("");
                    }
                }
                free(buf);
            }
            fclose(f);
        }
    }
}
