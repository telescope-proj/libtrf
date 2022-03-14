#include <trf_platform.h>

struct TRFNet *netDb;

int trfParseConfig(char *configFile){
    if (!configFile)
    {
        return -EINVAL;
    }
    netDb = calloc(1, sizeof(*netDb));
    if (!netDb)
    {
        trf__log_error("Unable to allocate TRFNet database");
        return -ENOMEM;
    }

    FILE *fp = fopen(configFile, "r");
    if (fp == NULL)
    {
        printf("Error opening: %s\n", configFile);
        return -1;
    }
    const unsigned MAX_LENGTH = 64;
    char buffer[MAX_LENGTH];
    char *token, *splitAddr;
    uint8_t iter = 0;
    int index = 0;
    int ret = 0;
    struct TRFNet *out_tmp = calloc(1, sizeof(*out_tmp));
    if (!out_tmp)
    {
        printf("Unable to allocate: out_tmp\n");
        ret = -ENOMEM;
        goto close_fd;
    }

    struct TRFNet *out_start = out_tmp;
    struct TRFNet *out_prev = NULL;

    while (fgets(buffer, MAX_LENGTH, fp))
    {   
        if (strcmp(buffer,"\n"  ) != 0 && strcmp(buffer,"\r\n") != 0 &&
            strcmp(buffer,"\0"  ) != 0 &&
        1)
        {
            token = strtok(buffer," "); 
            if (token)
            {
                while (token)
                {
                    switch (iter)
                    {
                    case 0:
                        if (strncmp(token, "linklocal", 
                            sizeof("linklocal") - 1) == 0)
                        {
                            out_tmp->type = TRF_NET_LINK_LOCAL;

                        }
                        else if (strncmp(token, "local", 
                            sizeof("local") - 1) == 0)
                        {
                            out_tmp->type = TRF_NET_LOCAL;
                        }
                        else
                        {
                            printf("Invalid type passed for type\n");
                            ret = -EINVAL;
                            goto close_fd;
                        }
                        token = strtok(NULL, " ");
                        iter ++;
                        break;
                    case 1:
                        if (strncmp(token, "ipv4", 
                            sizeof("ipv4") - 1) == 0)
                        {
                            out_tmp->name = TRF_NET_ADDR;
                            out_tmp->sa.ss_family = AF_INET;
                        }
                        else if (strncmp(token, "ipv6", 
                            sizeof("ipv6") - 1) == 0)
                        {
                            out_tmp->name = TRF_NET_ADDR;
                            out_tmp->sa.ss_family = AF_INET6;
                        }
                        else if (strncmp(token, "interface", 
                            sizeof("interface") - 1) == 0)
                        {
                            out_tmp->name = TRF_NET_IFNAME;
                        }
                        else if (strncmp(token, "blacklist", 
                            sizeof("blacklist") - 1) == 0)
                        {
                            out_tmp->name = TRF_NET_BLACKLIST;
                        }
                        else
                        {
                            printf("Invalid type passed for name\n");
                            ret = -EINVAL;
                            goto close_fd;
                        }
                        token = strtok(NULL, " ");
                        iter ++;
                        break;
                    case 2:
                        switch (out_tmp->name)
                        {
                        case TRF_NET_ADDR:
                            splitAddr = strtok(token, "/");
                            if (!splitAddr){
                                ret = -EINVAL;
                                printf("Unable to parse ip addrress\n");
                                goto close_fd;
                            }
                            while(token){
                                switch (index)
                                {
                                case 0:
                                    if (out_tmp->sa.ss_family == AF_INET)
                                    {
                                        ((struct sockaddr_in *) 
                                            &out_tmp->sa)->sin_family = AF_INET;                                  
                                        if(trfConvertCharToAddr(token, 
                                        ((struct sockaddr *) &out_tmp->sa)) < 0){
                                            printf("Unable to convert char to address\n");
                                            goto close_fd;
                                        }
                                    }
                                    else if (out_tmp->sa.ss_family == AF_INET6)
                                    {
                                        ((struct sockaddr_in6 *) 
                                            &out_tmp->sa)->sin6_family = AF_INET6;
                                        if(trfConvertCharToAddr(token, 
                                            ((struct sockaddr *) &out_tmp->sa)) < 0){
                                            printf("Unable to convert char to address\n");
                                            goto close_fd;
                                        }
                                    }
                                    token = strtok(NULL, "");
                                    index ++;
                                    break;
                                case 1:
                                    out_tmp->subnet = atoi(token);
                                    token = strtok(NULL, "");
                                    index = 0;
                                    break;
                                default:
                                    printf("Invalid ip address\n");
                                    goto close_fd;
                                }
                            }
                            break;
                        case TRF_NET_IFNAME:
                            out_tmp->ifname = strdup(token);
                            break;
                        case TRF_NET_BLACKLIST:
                            out_tmp->ifname = strdup(token);
                            break;
                        }
                        token = strtok(NULL, " ");
                        iter ++;
                        break;
                    }
                }
                iter = 0;
                out_tmp->next = calloc(1, sizeof(struct TRFNet));
                if (!out_tmp->next){
                    fclose(fp);
                    return -ENOMEM;
                }
                out_prev = out_tmp;
                out_tmp = out_tmp->next;
            }
            else
            {
                printf("Unable to parse config file\n");
            }
        }
    }
    free(out_tmp);
    out_prev->next = NULL;
    *netDb = *out_start;


close_fd:
    fclose(fp);
    return ret;
}