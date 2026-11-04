#ifndef TIMESTAMP_H
#define TIMESTAMP_H

#include <sys/types.h>

void timestamp_set(uid_t);
int  timestamp_check(uid_t);
void timestamp_clear(uid_t);

#endif