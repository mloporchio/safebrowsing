# safebrowsing
An experimental command-line utility for Google Safe Browsing website categorization tool.
This command-line utility allows you to perform queries to Google Safe Browsing database in order to classify a website and to discover whether it is malicious or not.<br>
To compile the program, just run <code>gcc -o safebrowsing safebrowsing.c -lcurl</code>.<br>
To run the program: <code>./safebrowsing URL<code>, where <code>URL</code> is the address of the website you'd like to check.
