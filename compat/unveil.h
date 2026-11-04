#ifndef UNVEIL_H
#define UNVEIL_H

int unveil(const char *, const char *);
int unveil_commit(void);
int unveil_core_paths(void);

#endif