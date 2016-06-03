/*
	safebrowsing

	This is an experimental website/domain categorization tool
	based on Google Safe Browsing API.
	It is a simple command-line utility to perform queries to
	the Safe Browsing database.
	
	Author: Matteo Loporchio
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#define CATEGORIZATION_URL "https://sb-ssl.google.com/safebrowsing/api/lookup"
#define CLIENT "safebrowsing"
#define APPVER "1.0"
#define PVER "3.0"
#define ASIZE 36
#define KSIZE 512
#define BSIZE 4096
#define KEY_FILENAME "categorization.key"
#define REPLY_SAFE "safe"

/*
	The following buffer will be used to store information
	while performing requests using libcurl.
*/
typedef struct {
	char *s;
	size_t l;
} buffer_t;

/*
	This function creates a new buffer and returns a pointer to it.
	The function returns NULL if memory allocation fails.
*/
buffer_t *newBuffer() {
	buffer_t *buf = malloc(sizeof(buffer_t));
	if (buf) {
		buf -> l = 0;
		buf -> s = calloc(1, sizeof(char));
		if (!(buf -> s)) {
			free(buf);
			return NULL;
		}
		return buf;
	}
	return NULL;
}

/*
	This callback function will be passed to 'curl_easy_setopt' in order
	to write curl output to a variable.
*/
size_t write_f(void *ptr, size_t size, size_t nmemb, buffer_t *buf) {
	size_t buf_len = buf -> l, new_len = buf_len + (size * nmemb);
	buf -> s = realloc(buf -> s, new_len + 1);
	if (!(buf -> s)) return 0;
	memcpy((buf -> s) + buf_len, ptr, size * nmemb);
	buf -> s[new_len] = '\0';
	buf -> l = new_len;
	return (size * nmemb);
}

/*
	Returns 1 if the character is alphanumeric, 0 otherwise.
*/
int isAlpha(char code) {
	static char alpha[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	int i = 0;
	while (i < ASIZE) {
		if (code == alpha[i]) return 1;
		i++;
	}
	return 0;
}

/* 
	Converts an integer value to its hex character.
	Many thanks to: http://www.geekhideout.com/downloads/urlcode.c
*/
char toHex(char code) {
	static char hex[] = "0123456789abcdef";
	return hex[code & 15];
}

/*
	The following function encodes a URL string in hexadecimal format.
	Many thanks to: http://www.geekhideout.com/downloads/urlcode.c
*/
char *urlEncode(char *url) {
	if (!url) return NULL;
	unsigned int url_len = strlen(url);
	char *pstr = url, *buf = malloc((3 * url_len) + 1);
	if (!buf) return NULL;
	char *pbuf = buf;	
	while (*pstr) {
		if (isAlpha(*pstr) || *pstr == '-' || *pstr == '_' ||
		*pstr == '.' || *pstr == '~') *pbuf++ = *pstr;
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

/*
	This function performs a GET operation using libcurl,
	starting from URL and storing the HTTP reply code
	in the 'http_code' parameter.
	The function returns a string containing the operation output.
*/
char *curlGet(char *URL, long *http_code, CURLcode *exit_code) {
	CURL *curl;
	CURLcode result;
	long reply_code = 0;
	if ((curl = curl_easy_init())) {
		buffer_t *reply_buf = newBuffer();
		if (!reply_buf) {
			curl_easy_cleanup(curl);
			return NULL;
		}
		curl_easy_setopt(curl, CURLOPT_URL, URL);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_f);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, reply_buf);
		result = curl_easy_perform(curl);
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &reply_code);
		*exit_code = result;
		*http_code = reply_code;
		curl_easy_cleanup(curl);
		return (reply_buf -> s);
	}
	return NULL;
}

/*
	NOTICE: Remember to call the program by passing the URL
	as first (and unique) parameter!
*/
int main(int argc, char const *argv[]) {
	FILE *keyfile = NULL;
	int result = 0; 
	long http_reply = 0;
	CURLcode curl_exit;
	char *get_result = NULL, *encoded_url = NULL;
	char apikey[KSIZE], request_url[BSIZE], request_reply[BSIZE];

	// Checking arguments.
	if (argc < 2) {
		fprintf(stderr,
		"Error: please supply a valid URL.\n");
		return EXIT_FAILURE;
	}

  	// Checking if the key is already stored in file "categorization.key".
	memset(apikey, 0, sizeof(apikey));
	keyfile = fopen(KEY_FILENAME, "r");
  	if (keyfile) {
		// File already exists. Reading the key from the file.
		if (!fgets(apikey, sizeof(apikey), keyfile)) {
			fprintf(stderr,
			"Something went wrong while reading from file.\n");
			return EXIT_FAILURE;
		}		
	}
	else {
		/* 
			File does not exist. We create the file and ask for
			the key to be stored in it.
		*/
		fprintf(stdout, "Please insert your categorization key below.\n");
		fscanf(stdin, "%s", apikey);
		keyfile = fopen(KEY_FILENAME, "w+");
		if (keyfile) {
			result = fputs(apikey, keyfile);
			fclose(keyfile);
			if (result < 0) {
				fprintf(stderr,
				"Something went wrong while writing to file.\n");
				return EXIT_FAILURE;
			}
		}
		else {
			fprintf(stderr,
			"Something went wrong while creating the file.\n");
			return EXIT_FAILURE;
		}
	}

	// Creating request URL.
	encoded_url = urlEncode((char *) argv[1]);
	snprintf(request_url, sizeof(request_url), 
	"%s?client=%s&apikey=%s&appver=%s&pver=%s&url=%s",
	CATEGORIZATION_URL, CLIENT, apikey,
	APPVER, PVER, encoded_url);
	free(encoded_url);

	// Performing request.
	get_result = curlGet(request_url, &http_reply, &curl_exit);
	if (!get_result) {
		fprintf(stderr,
		"Error: curl request failed.\n");
		return EXIT_FAILURE;
	}
	if (curl_exit != CURLE_OK) {
		fprintf(stderr,
		"Error: curl request failed with code %s.\n",
		curl_easy_strerror(curl_exit));
		free(get_result);
		return EXIT_FAILURE;
	}
	// Copying result.
	memcpy(request_reply, get_result, sizeof(request_reply));
	free(get_result);

	// Checking if request reply is empty.
	if (request_reply[0] == '\0') {
		snprintf(request_reply, sizeof(request_reply), REPLY_SAFE);
	}
	// Checking reply code.
	if (!http_reply) {
		fprintf(stderr, 
		"Something went wrong while performing your request.\n");
		return EXIT_FAILURE; 
	}
	else {
		fprintf(stdout,
		"GET request performed correctly with URL: %s\n\n", request_url);
		switch (http_reply) {
			case 200: {
				fprintf(stdout, "%s\n\n%s %s %s %s.\n\n",
				"Your code is: 200 OK.",
				"The website", argv[1], "seems to be",
				request_reply);
			}; break;
			case 204: {
				fprintf(stdout, "%s\n\n%s %s %s %s.\n\n",
				"Your code is: 204 NO CONTENT.",
				"The website", argv[1], "seems to be",
				request_reply);
			}; break;
			case 400: {
				fprintf(stderr, "%s %s\n",
				"Your code is: 400 BAD REQUEST.",
				"(Please check the syntax of your URL!)");
			}; break;
			default: {
				fprintf(stdout, "Your code is: %ld\n",
				http_reply);
			}; break;
		}
	}
	return EXIT_SUCCESS;
}
