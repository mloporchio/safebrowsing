/*
  This is an experimental website/domain categorization tool based on Google Safe Browsing API.
  It is a simple command-line utility to perform queries to the Safe Browsing database.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#define CATEGORIZATION_URL "https://sb-ssl.google.com/safebrowsing/api/lookup"
#define CLIENT "ntopng"
#define APIKEY "ABQIAAAAXvY7RNqD0ZXs1w0jW2CGTRS9IRPbEtejJMhL9X_PdOU4Y_zLPg"
#define APPVER "1.0"
#define PVER "3.0"

// We use the following struct to represent strings.
// They will be useful for storing the libcurl GET function output in a variable.

typedef struct _string {
  char *s;
  size_t l;
} String;

// The following one initializes a new string.
void newString(String *str) {
  str->l = 0;
  str->s = (char *) malloc((str->l) + 1);
  if (str->s == NULL) {
    fprintf(stderr, "ERROR: malloc() failed!\n");
    exit(EXIT_FAILURE);
  }
  else {
    str->s[0] = '\0';
  }
  return;
}

// This callback function will be passed to 'curl_easy_setopt' in order to write curl output to a variable.
size_t writeFunc(void *ptr, size_t size, size_t nmemb, String *str) {
  size_t new_len = str->l + (size * nmemb);
  str->s = realloc(str->s, new_len + 1);
  if (str->s == NULL) {
    fprintf(stderr, "ERROR: realloc() failed!\n");
    exit(EXIT_FAILURE);
  }
  memcpy(str->s+str->l, ptr, size * nmemb);
  str->s[new_len] = '\0';
  str->l = new_len;

  return (size * nmemb);
}

// The following functions are used as support methods for 'urlEncode'.
char toHex(char c) {
  char hex[] = "0123456789ABCDEF";
  return hex[c & 15];
}

int isAlphanum(char c) {
  int i;
  char alphanum[] = "0123456789abcdefghijklmnopqrstuvwxyz";
  for (i = 0; i < 36; i++) {
    if (c == alphanum[i]) return 1;
  }
  return 0;
}

// The following function encodes a URL string in hexadecimal format.
char *urlEncode(char *URL) {
  char *pstr = URL;
  char *buf = (char *) malloc(strlen(URL) * 3 + 1);
  char *pbuf = buf;
  while (*pstr) {
    if (isAlphanum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') {
      *pbuf++ = *pstr;
    }
    else {
      if (*pstr == ' ') *pbuf++ = '+';
      else {
        *pbuf++ = '%';
        *pbuf++ = toHex(*pstr >> 4);
        *pbuf++ = toHex(*pstr & 15);
      }
    }
    pstr++;
  }
  *pbuf = '\0';
  return buf;
}

// This function performs a GET operation using libcurl, starting from URL and storing the HTTP reply code in the 'http_code' parameter.
// The function returns a string containing the operation output.
char *curlGet(char *URL, long *http_code) {
  CURL *curl;
  CURLcode res;
  String replyString;
  long replyCode = 0;

  curl = curl_easy_init();
  if (curl) {
    newString(&replyString);
    curl_easy_setopt(curl, CURLOPT_URL, URL);
    //curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // Uncomment this for redirection support.
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &replyString);
    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &replyCode);
    if (res != CURLE_OK) {
      fprintf(stderr, "ERROR: curl_easy_perform failed with code %s.\n", curl_easy_strerror(res));
    }
    *http_code = replyCode;
    curl_easy_cleanup(curl);
    return replyString.s;
  }
  return NULL;
}

// NOTICE: Remember to call the program by passing the URL as first (and unique) parameter!
int main(int argc, char const *argv[]) {
  long reply = 0;
  //char BASE_URL[] = "http://ianfette.org"; // An example of malicious domain.
  char REQUEST_URL[1024];
  char REQUEST_REPLY[1024];
  snprintf(REQUEST_URL, sizeof(REQUEST_URL), "%s?client=%s&apikey=%s&appver=%s&pver=%s&url=%s", CATEGORIZATION_URL, CLIENT, APIKEY,
    APPVER, PVER, urlEncode((char *) argv[1]));

  snprintf(REQUEST_REPLY, sizeof(REQUEST_REPLY), "%s", curlGet(REQUEST_URL, &reply));
  //printf("%s\n", REQUEST_REPLY);
  //printf("\n");

  if (REQUEST_REPLY[0] == '\0') {
    snprintf(REQUEST_REPLY, sizeof(REQUEST_REPLY), "good");
  }


  printf("GET request performed correctly with URL: %s\n", REQUEST_URL);
  if (reply == 0) {
    printf("Something went wrong, but the error is yours!\n");
  }
  else {
    if (reply == 200) {
      printf("Everything went fine, your code is 200: OK.\n");
      printf("\n");
      printf("The website %s seems to be %s.\n", argv[1], REQUEST_REPLY);
      printf("\n");
    }
    else {
      if (reply == 204) {
        printf("Everything went fine, your code is 204: NO CONTENT.\n");
        printf("\n");
        printf("The website %s seems to be %s.\n", argv[1], REQUEST_REPLY);
        printf("\n");
      }
      else {
        if (reply == 400) {
          printf("The request you performed was invalid, your code is 400: BAD REQUEST.\n");
        }
        else printf("Your code was: %ld\n", reply);
      }
    }
  }
  return 0;
}
