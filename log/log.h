#ifndef __LOG_H
#define __LOG_H

#ifdef _WIN32
# define LogMessage(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__), fputc('\n', stderr), fflush(stderr)
#else
# ifdef NDEBUG
#  define l_debug(format...)
#  define DebugLog
# else
#  define l_debug(format...) do {               \
         l_debug_(__FUNCTION__, ## format);     \
     } while (false)
#  define DebugLog l_debug
# endif

# define l_message(format...) do {              \
        l_message_(__FUNCTION__, ## format);    \
    } while (false)

# define l_warning(format...) do {              \
        l_warning_(__FUNCTION__, ## format);    \
    } while (false)

# define l_error(format...) do {                \
        l_error_(__FUNCTION__, ## format);      \
    } while (false)

// A more windowsy looking routine.
# define LogMessage(format...) do {             \
         l_message_(__FUNCTION__, ## format);   \
     } while (false)
#endif

void l_message_(const char *function, const char *format, ...);
void l_debug_(const char *function, const char *format, ...);
void l_warning_(const char *function, const char *format, ...);
void l_error_(const char *function, const char *format, ...);

#endif
