#ifndef UTILS_H_
#define UTILS_H_

#include <stdlib.h>
#include <stdio.h>

#define LEVEL_ERROR 0x00
#define LEVEL_WARN 0x01
#define LEVEL_INFO 0x02
#define LEVEL_DEBUG 0x03

#define ERROR_TAG "ERROR"
#define WARN_TAG "WARN"
#define INFO_TAG "INFO"
#define DEBUG_TAG "DEBUG"

#ifndef LOG_LEVEL
#define LOG_LEVEL LEVEL_DEBUG
#endif

#define LOG_PRINT(level_tag, fmt, ...) \
  fprintf(stdout, "%s\t%s\t%d\t" fmt"\n", level_tag, __FILE__, __LINE__, ##__VA_ARGS__)

#if LOG_LEVEL >= LEVEL_DEBUG
#define LOGD(fmt, ...) LOG_PRINT(DEBUG_TAG, fmt, ##__VA_ARGS__)
#else
#define LOGD(fmt, ...)
#endif

#if LOG_LEVEL >= LEVEL_INFO
#define LOGI(fmt, ...) LOG_PRINT(INFO_TAG, fmt, ##__VA_ARGS__)
#else
#define LOGI(fmt, ...)
#endif

#if LOG_LEVEL >= LEVEL_WARN
#define LOGW(fmt, ...) LOG_PRINT(WARN_TAG, fmt, ##__VA_ARGS__)
#else
#define LOGW(fmt, ...)
#endif

#if LOG_LEVEL >= LEVEL_ERROR
#define LOGE(fmt, ...) LOG_PRINT(ERROR_TAG, fmt, ##__VA_ARGS__)
#else
#define LOGE(fmt, ...)
#endif

void utils_random_string(char *s, const int len);

#endif // UTILS_H_

