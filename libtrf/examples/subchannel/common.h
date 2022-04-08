#ifndef TRF_DEMO_SUBCH_COMMON_H
#define TRF_DEMO_SUBCH_COMMON_H

const char * port = "33000";

#define ts_printf(...) do {         \
    pthread_mutex_lock(&mut);       \
    printf(__VA_ARGS__);            \
    fflush(stdout);                 \
    pthread_mutex_unlock(&mut);     \
} while (0);                        \

#define timespecdiff(_start, _end) \
        (((_end).tv_sec - (_start).tv_sec) * 1000000000 + \
        ((_end).tv_nsec - (_start).tv_nsec))

#endif