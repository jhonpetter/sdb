#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "strutils.h"
#include "utils.h"
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

size_t tokenize(const char *str, const char *delim, char *tokens[], size_t max_tokens ) {
    int cnt = 0;

    char tmp[PATH_MAX];

    strncpy(tmp, str, PATH_MAX - 1);
    char *p = strtok(tmp, delim);
    if (max_tokens < 1 || max_tokens > MAX_TOKENS) {
        max_tokens = MAX_TOKENS;
    }

    if (p != NULL) {
        tokens[cnt++] = strdup(p);
        while(cnt < max_tokens && p != NULL) {
            p = strtok(NULL, delim);
            if (p != NULL) {
                tokens[cnt++] = strdup(p);
            }
        }
    }
    return cnt;
}

void free_strings(char **array, int n)
{
    int i;

    for(i = 0; i < n; i++) {
        SAFE_FREE(array[i]);
    }
}

int read_lines(const int fd, char* ptr, unsigned int maxlen)
{
    int lines = 0;
    while (1) {
        int len = read_line(fd, ptr, maxlen);
        if(len < 0) {
            break;
        }
        ptr += len;
        *ptr++ = '\n';
        len++;
        maxlen -= len;
        lines++;
    }
    return lines;
}

int read_line(const int fd, char* ptr, const unsigned int maxlen)
{
    unsigned int n = 0;
    char c[2];

    while(n != maxlen) {
        if(sdb_read(fd, c, 1) != 1) {
            break;
        }
        if(*c == '\r') {
            continue;
        }
        if(*c == '\n') {
            ptr[n] = 0;
            return n;
        }
        ptr[n++] = *c;
    }
    return -1; // no space
}

/**
 * The standard strncpy() function does not guarantee that the resulting string is null terminated.
 * char ntbs[NTBS_SIZE];
 * strncpy(ntbs, source, sizeof(ntbs)-1);
 * ntbs[sizeof(ntbs)-1] = '\0'
 */
char *s_strncpy(char *dest, const char *source, size_t n) {

    char *start = dest;

    if (n) {
        while (--n) {
            if (*source == '\0') {
                break;
            }
            *dest++ = *source++;
        }
        *dest = '\0';
    }

    return start;
}

/**
 * Mingw doesn't have strnlen.
 */
size_t s_strnlen(const char *s, size_t maxlen) {
    size_t len;
    for (len = 0; len < maxlen; len++, s++) {
       if (!*s) {
            break;
       }
    }
    return len;
}

char* strlchr(const char*s, int chr) {
    if(s == NULL) {
        return NULL;
    }
    int len = s_strnlen(s, PATH_MAX);
    int i = len - 1;
    for(; i>-1; i--) {
        if(s[i] == chr) {
            fflush(stdout);
            return (char*)(s + i);
        }
    }

    return NULL;
}

//LCOV_EXCL_START
char* trim(char *s) {
    rtrim(s);
    return ltrim(s);
}

void rtrim(char* s) {

    int len = s_strnlen(s, PATH_MAX) - 1;
    char* t = s + len;

    for(; len > -1; len--) {
        if(*t != ' ') {
            *(t+1) = '\0';
            break;
        }
        t--;
    }
}

char* ltrim(char *s) {
    char* begin;
    begin = s;

    while (*begin != '\0') {
        if (*begin == ' ')
            begin++;
        else {
            s = begin;
            break;
        }
    }

    return s;
}

/*
  Splits s into multiple lines of width w. Returns the number of
  lines. line_ret will be set to an array of string pointers, each
  pointing to the start of a line. len_ret will be set to an array of
  ints, describing how wide the corresponding line is. If an error
  occurs 0 is returned; line_ret and len_ret are then left unmodified.
*/
int strwrap(char * s, int w, char *** line_ret, int ** len_ret) {
    int allocated; /* lines allocated */
    int lines; /* lines used */
    char ** line;
    int * len;
    int tl; /* total length of the string */
    int l; /* length of current line */
    int p; /* offset (from s) of current line */
    int close_word;
    int open_word;
    int i;

    if (s == NULL)
        return 0;

    tl = strlen(s);

    if (tl == 0 || w <= 0)
        return 0;

    lines = 0;

    /*
     Preemptively allocate memory. This should be enough for most uses;
     if we need more we will realloc later.
     */
    allocated = (tl / w) * 1.5 + 1;

    line = (char **) malloc(sizeof(char *) * allocated);
    if (line == NULL) {
        return 0;
    }

    len = (int *) malloc(sizeof(int) * allocated);
    if (len == NULL) {
        free(line);
        return 0;
    }

    /*
     p will be an offset from the start of the string and the start of
     the current line we are processing.
     */

    p = 0;

    while (p < tl) {
        /* Detect initial newlines */
        if (s[p] == '\n') {
            l = 0;
            goto make_new_line;
        }

        /*
         Fast-forward past initial whitespace on the current line. You
         might want to comment this out if you need formatting like
         "  * Bullet point lists" and wish to preserve the spaces.
         */
        if (isspace(s[p])) {
            p++;
            continue;
        }

        /*
         Decide how long the current line should be. We typically want
         the line to take up the full allowed line width, but we also
         want to limit the perceived length of the final line. If the
         line width overshoots the end of the string, truncate it.
         */
        if (p + w > tl)
            w = tl - p;

        l = w;

        /*
         If the break point ends up within a word, count how many
         characters of that word fall outside the window to the right.
         */
        close_word = 0;

        while (s[p + l + close_word] != '\0' && !isspace(s[p + l + close_word]))
            close_word++;

        /*
         Now backtrack from the break point until we find some
         whitespace. Keep track of how many characters we traverse.
         */
        open_word = 0;

        while (s[p + l] != '\0' && !isspace(s[p + l])) {
            l--;
            open_word++;

            /*
             If the current word length is near the line width it will be
             hard to fit it all on a line, so we should just leave as much
             of it as possible on this line. Remove the fraction if you
             only want longer words to break.
             */
            if (open_word + close_word > w * 0.8) {
                l = w;
                break;
            }
        }

        /*
         We now have a line width we wish to use. Just make a final check
         there are no newlines in the middle of the line. If there are,
         break at that point instead.
         */
        for (i = 0; i < l; i++) {
            if (s[p + i] == '\n') {
                l = i;
                break;
            }
        }

        make_new_line:
        /*
         We have decided how long this line should be. Check that we have
         enough memory reserved for the line pointers; allocate more if
         needed.
         */

        line[lines] = &s[p];
        len[lines] = l;
        lines++;

        if (lines >= allocated) {
            allocated *= 2;

            line = (char **) realloc(line, sizeof(char *) * allocated);
            len = (int *) realloc(len, sizeof(int) * allocated);

            if (line == NULL || len == NULL)
                return 0;
        }

        /*
         Move on to the next line. This needs to be 1 less than the
         desired width or we will drop characters in the middle of
         really long words.
         */
        if (l == w)
            l--;

        p += l + 1;
    }

    /* Finally, relinquish memory we don't need */
    line = (char **) realloc(line, sizeof(char *) * lines);
    len = (int *) realloc(len, sizeof(int) * lines);

    *line_ret = line;
    *len_ret = len;

    return lines;
}
//LCOV_EXCL_STOP
