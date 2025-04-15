/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of OCEAN's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://ocean.xyz
 *
 * ---
 *
 * Copyright (c) 2024 Bitcoin Ocean, LLC & Luke Dashjr
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <assert.h>
#include <string.h>

#include "datum_conf.h"
#include "datum_stratum.h"

void datum_stratum_relevant_username_tests() {
	char buf[0x100];
	char * const pool_addr = datum_config.mining_pool_address;
	char *s;
	
	strcpy(pool_addr, "dummy");
	s = "abc";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == s);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == s);
	s = "";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == s);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == s);
	s = "abc%def";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == s);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == s);
	s = "abc%0%def";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == &s[6]);
	s = "abc%0%def%ghi";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == &s[6]);
	s = "abc%0%def%0%ghi";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == &s[12]);
	s = "abc%0%def%1%ghi";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "def"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x28e) == buf);
	assert(!strcmp(buf, "def"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x28f) == &s[12]);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == &s[12]);
	s = "abc%1%def%1%ghi";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "abc"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x28e) == buf);
	assert(!strcmp(buf, "abc"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x28f) == buf);
	assert(!strcmp(buf, "def"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x51d) == buf);
	assert(!strcmp(buf, "def"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x51e) == &s[12]);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == &s[12]);
	s = "abc%1%def%1%ghi%1";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "abc"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x28e) == buf);
	assert(!strcmp(buf, "abc"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x28f) == buf);
	assert(!strcmp(buf, "def"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x51d) == buf);
	assert(!strcmp(buf, "def"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x51e) == buf);
	assert(!strcmp(buf, "ghi"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x7ac) == buf);
	assert(!strcmp(buf, "ghi"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x7ad) == pool_addr);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == pool_addr);
	s = "abc%.01%def";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "abc"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 5) == buf);
	assert(!strcmp(buf, "abc"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 6) == &s[8]);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == &s[8]);
	s = "abc%55.%def";
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "abc"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x8ccb) == buf);
	assert(!strcmp(buf, "abc"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x8ccc) == &s[8]);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == &s[8]);
	s = "abc%55.55%def";
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "abc"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x8e34) == buf);
	assert(!strcmp(buf, "abc"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x8e35) == &s[10]);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == &s[10]);
	s = "abc%99.99%def";
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "abc"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xfff8) == buf);
	assert(!strcmp(buf, "abc"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xfff9) == &s[10]);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == &s[10]);
	s = "abc%100%def";
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "abc"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == buf);
	assert(!strcmp(buf, "abc"));
	s = "a%10%b%10%c%10%d%10%e%10%f%10%g%10%h%10%i%10%j%10";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == buf);
	assert(!strcmp(buf, "j"));
	memset(buf, 5, 5);
	s = "a%10%b%10%c%10%d%10%e%10%f%10%g%10%h%10%i%10%j%10%k";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == buf);
	assert(!strcmp(buf, "j"));
	
	// Test URL-encoded percentages
	s = "user1%25";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "user1"));
	
	s = "user1%50%user2%25";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "user1"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == buf);
	assert(!strcmp(buf, "user2"));
	
	// Test with 3 users and URL-encoded percentages
	s = "user1%50%user2%25%user3%25";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "user1"));
	
	// Test with the specific username from the issue
	s = "bc1qrandomaddress000000000000000000.TESTING%50%bc1qrandomaddress000000000000000001.TESTING%25%bc1qrandomaddress000000000000000002.TESTING2%25";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "bc1qrandomaddress000000000000000000.TESTING"));
	
	// Test ambiguous patterns where a sequence could be interpreted as either percentage or URL-encoded character
	s = "user1%25%75"; // Test case where %25 is a 25% split, not a URL-encoded '%'
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "user1"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x7000) == &s[7]); // Verify distribution above 25% threshold
	
	// Test the actual format that was reported problematic
	s = "bc1qrandomaddress000000000000000000.TESTING%25%bc1qrandomaddress000000000000000001.TESTING%75";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "bc1qrandomaddress000000000000000000.TESTING"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x8000) == &s[42]); // Verify distribution above 25% threshold
	
	// Test handling of various URL-encoded characters
	// Test with URL-encoded space character
	s = "user1%50%user2%20%user3";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "user1"));
	
	// Test with URL-encoded ampersand character
	s = "user1%50%user2%26%user3";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "user1"));
	
	// Test edge cases with URL-encoded characters
	s = "user1%20%user2"; // URL-encoded space at the beginning of potential percentage
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "user1"));
	
	s = "user1%50%user2%20"; // URL-encoded space at the end of username
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "user1"));
	
	// Additional edge cases
	// Test with very large percentages
	s = "user1%99.99%user2%0.01";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "user1"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xfffe) == &s[12]); // Just below 100%
	
	// Test with sequential URL-encoded characters
	s = "user1%20%20%user2"; // Two URL-encoded spaces in a row
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "user1"));
	
	// Test with mixed URL-encoded characters
	s = "user1%25%20%user2"; // URL-encoded % followed by URL-encoded space
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "user1"));
	
	// Test with malformed percentages that should be rejected
	s = "user1%101%user2"; // Invalid percentage > 100%
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == s);
	
	s = "user1%-1%user2"; // Invalid negative percentage
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == s);
	
	// Test consecutive percentage delimiters
	s = "user1%%user2"; // Empty percentage value
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == s);
	
	// Test extremely long usernames
	char long_username[256] = "user1%50%";
	memset(long_username + 7, 'A', 240);
	long_username[247] = 0;
	assert(datum_stratum_relevant_username(long_username, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "user1"));
	
	// Test boundary case where share_rnd is exactly at the threshold
	s = "user1%50%user2%50";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x7FFF) == buf); // Just below 50%
	assert(!strcmp(buf, "user1"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x8000) == &s[7]); // Exactly at 50%
	assert(!strcmp(buf, "user2"));
	
	// Test the specific pattern where %20 is a percentage value, not URL-encoded space
	s = "bc1qrandomaddress000000000000000000.TESTING%20%bc1qrandomaddress000000000000000001.TESTING%80";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "bc1qrandomaddress000000000000000000.TESTING"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x5000) == &s[42]); // Verify distribution above 20% threshold
}

void datum_stratum_tests(void) {
	datum_stratum_relevant_username_tests();
}
