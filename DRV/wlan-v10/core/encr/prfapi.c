/** @file prfapi.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2002-2020 NXP
  *
  * This software file (the "File") is distributed by NXP
  * under the terms of the GNU General Public License Version 2, June 1991
  * (the "License").  You may use, redistribute and/or modify the File in
  * accordance with the terms and conditions of the License, a copy of which
  * is available by writing to the Free Software Foundation, Inc.,
  * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
  * worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
  *
  * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
  * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
  * this warranty disclaimer.
  *
  */

/*
        
        File:            WPA.m
        Program:        KisMAC
        Author:            Michael Rossberg
                        mick@binaervarianz.de
        Description:    KisMAC is a wireless stumbler for MacOS X.
                
        This file is part of KisMAC.
 
    KisMAC is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
 
    KisMAC is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with KisMAC; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <linux/string.h>
#include "sha1.h"
#include "encryptapi.h"

/*
* PRF -- Length of output is in octets rather than bits
*     since length is always a multiple of 8 output array is
*     organized so first N octets starting from 0 contains PRF output
*
*     supported inputs are 16, 32, 48, 64
*     output array must be 80 octets to allow for sha1 overflow
*/
void
Mrvl_PRF(unsigned char *key, int key_len,
	 unsigned char *prefix, int prefix_len,
	 unsigned char *data, int data_len, unsigned char *output, int len)
{
	int i;
	// - 64: yield the resource
	unsigned char input[1024 - 64];	/* concatenated input */
	int currentindex = 0;
	int total_len;

	memcpy(input, prefix, prefix_len);
	input[prefix_len] = 0;	/* single octet 0 */
	memcpy(&input[prefix_len + 1], data, data_len);
	total_len = prefix_len + 1 + data_len;
	input[total_len] = 0;	/* single octet count, starts at 0 */
	total_len++;
	for (i = 0; i < (len + 19) / 20; i++) {
		Mrvl_hmac_sha1(input, total_len, key, key_len,
			       &output[currentindex]);
		currentindex += 20;	/* next concatenation location */
		input[total_len - 1]++;	/* increment octet count */
	}
}
