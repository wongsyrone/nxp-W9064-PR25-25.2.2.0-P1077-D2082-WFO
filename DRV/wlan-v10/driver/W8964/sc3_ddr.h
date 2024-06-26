/** @file sc3_ddr.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2018-2020 NXP
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
unsigned char ddr_init[] = {
	0x05,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0xec,
	0x05,
	0x00,
	0x00,
	0x06,
	0x94,
	0x4e,
	0x33,
	0x00,
	0x00,
	0x00,
	0xa8,
	0x01,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x48,
	0x00,
	0x47,
	0x04,
	0x00,
	0x00,
	0x00,
	0x6f,
	0x02,
	0x00,
	0x00,
	0x08,
	0x00,
	0x00,
	0x00,
	0xf0,
	0xb5,
	0x00,
	0x21,
	0x0c,
	0x00,
	0x00,
	0x00,
	0x0f,
	0x20,
	0x00,
	0x07,
	0x10,
	0x00,
	0x00,
	0x00,
	0xc1,
	0x60,
	0x9a,
	0x4a,
	0x14,
	0x00,
	0x00,
	0x00,
	0x9a,
	0x49,
	0x8a,
	0x61,
	0x18,
	0x00,
	0x00,
	0x00,
	0x1b,
	0x22,
	0x42,
	0x61,
	0x1c,
	0x00,
	0x00,
	0x00,
	0x82,
	0x61,
	0xc2,
	0x61,
	0x20,
	0x00,
	0x00,
	0x00,
	0x98,
	0x48,
	0x42,
	0x68,
	0x24,
	0x00,
	0x00,
	0x00,
	0x92,
	0x08,
	0x92,
	0x00,
	0x28,
	0x00,
	0x00,
	0x00,
	0x01,
	0x32,
	0x42,
	0x60,
	0x2c,
	0x00,
	0x00,
	0x00,
	0x96,
	0x4a,
	0x82,
	0x60,
	0x30,
	0x00,
	0x00,
	0x00,
	0x12,
	0x0c,
	0xc2,
	0x60,
	0x34,
	0x00,
	0x00,
	0x00,
	0x95,
	0x4a,
	0x96,
	0x4b,
	0x38,
	0x00,
	0x00,
	0x00,
	0x1a,
	0x61,
	0x91,
	0x4b,
	0x3c,
	0x00,
	0x00,
	0x00,
	0x80,
	0x3b,
	0x1a,
	0x69,
	0x40,
	0x00,
	0x00,
	0x00,
	0x12,
	0x0a,
	0x12,
	0x02,
	0x44,
	0x00,
	0x00,
	0x00,
	0x06,
	0x32,
	0x1a,
	0x61,
	0x48,
	0x00,
	0x00,
	0x00,
	0xf1,
	0x22,
	0x8d,
	0x4c,
	0x4c,
	0x00,
	0x00,
	0x00,
	0x12,
	0x01,
	0xc0,
	0x3c,
	0x50,
	0x00,
	0x00,
	0x00,
	0x22,
	0x62,
	0x01,
	0x22,
	0x54,
	0x00,
	0x00,
	0x00,
	0x92,
	0x02,
	0x22,
	0x63,
	0x58,
	0x00,
	0x00,
	0x00,
	0x8e,
	0x4d,
	0x8f,
	0x4c,
	0x5c,
	0x00,
	0x00,
	0x00,
	0x25,
	0x60,
	0x8f,
	0x4d,
	0x60,
	0x00,
	0x00,
	0x00,
	0x25,
	0x61,
	0x8f,
	0x4d,
	0x64,
	0x00,
	0x00,
	0x00,
	0x25,
	0x62,
	0x8f,
	0x4d,
	0x68,
	0x00,
	0x00,
	0x00,
	0x25,
	0x63,
	0x41,
	0x24,
	0x6c,
	0x00,
	0x00,
	0x00,
	0xa4,
	0x04,
	0xc4,
	0x61,
	0x70,
	0x00,
	0x00,
	0x00,
	0x84,
	0x02,
	0x8c,
	0x60,
	0x74,
	0x00,
	0x00,
	0x00,
	0x8c,
	0x4c,
	0x04,
	0x62,
	0x78,
	0x00,
	0x00,
	0x00,
	0x8c,
	0x48,
	0x18,
	0x62,
	0x7c,
	0x00,
	0x00,
	0x00,
	0x8c,
	0x48,
	0x58,
	0x62,
	0x80,
	0x00,
	0x00,
	0x00,
	0x8c,
	0x48,
	0x08,
	0x63,
	0x84,
	0x00,
	0x00,
	0x00,
	0x7e,
	0x48,
	0x00,
	0x23,
	0x88,
	0x00,
	0x00,
	0x00,
	0x80,
	0x30,
	0x03,
	0x60,
	0x8c,
	0x00,
	0x00,
	0x00,
	0x01,
	0x24,
	0x04,
	0x61,
	0x90,
	0x00,
	0x00,
	0x00,
	0x7c,
	0x48,
	0x89,
	0x4b,
	0x94,
	0x00,
	0x00,
	0x00,
	0x40,
	0x38,
	0x43,
	0x60,
	0x98,
	0x00,
	0x00,
	0x00,
	0x88,
	0x4b,
	0x83,
	0x60,
	0x9c,
	0x00,
	0x00,
	0x00,
	0x88,
	0x4b,
	0x03,
	0x61,
	0xa0,
	0x00,
	0x00,
	0x00,
	0x00,
	0x23,
	0x0b,
	0x62,
	0xa4,
	0x00,
	0x00,
	0x00,
	0x0c,
	0x62,
	0x87,
	0x49,
	0xa8,
	0x00,
	0x00,
	0x00,
	0x0b,
	0x68,
	0xa3,
	0x43,
	0xac,
	0x00,
	0x00,
	0x00,
	0x0b,
	0x60,
	0xcd,
	0x69,
	0xb0,
	0x00,
	0x00,
	0x00,
	0x83,
	0x04,
	0x1d,
	0x43,
	0xb4,
	0x00,
	0x00,
	0x00,
	0xcd,
	0x61,
	0xcd,
	0x69,
	0xb8,
	0x00,
	0x00,
	0x00,
	0x9d,
	0x43,
	0xcd,
	0x61,
	0xbc,
	0x00,
	0x00,
	0x00,
	0xcd,
	0x69,
	0x9d,
	0x43,
	0xc0,
	0x00,
	0x00,
	0x00,
	0xcd,
	0x61,
	0xcd,
	0x69,
	0xc4,
	0x00,
	0x00,
	0x00,
	0x2b,
	0x43,
	0xcb,
	0x61,
	0xc8,
	0x00,
	0x00,
	0x00,
	0xcd,
	0x69,
	0x43,
	0x04,
	0xcc,
	0x00,
	0x00,
	0x00,
	0x9d,
	0x43,
	0xcd,
	0x61,
	0xd0,
	0x00,
	0x00,
	0x00,
	0xcd,
	0x69,
	0x1d,
	0x43,
	0xd4,
	0x00,
	0x00,
	0x00,
	0xcd,
	0x61,
	0xcd,
	0x69,
	0xd8,
	0x00,
	0x00,
	0x00,
	0x1d,
	0x43,
	0xcd,
	0x61,
	0xdc,
	0x00,
	0x00,
	0x00,
	0xcd,
	0x69,
	0x1d,
	0x43,
	0xe0,
	0x00,
	0x00,
	0x00,
	0xcd,
	0x61,
	0xcd,
	0x69,
	0xe4,
	0x00,
	0x00,
	0x00,
	0x1d,
	0x43,
	0xcd,
	0x61,
	0xe8,
	0x00,
	0x00,
	0x00,
	0xcd,
	0x69,
	0x1d,
	0x43,
	0xec,
	0x00,
	0x00,
	0x00,
	0xcd,
	0x61,
	0xcd,
	0x69,
	0xf0,
	0x00,
	0x00,
	0x00,
	0x9d,
	0x43,
	0xcd,
	0x61,
	0xf4,
	0x00,
	0x00,
	0x00,
	0x00,
	0x23,
	0xcb,
	0x62,
	0xf8,
	0x00,
	0x00,
	0x00,
	0xcc,
	0x62,
	0x73,
	0x4d,
	0xfc,
	0x00,
	0x00,
	0x00,
	0x01,
	0x3d,
	0xfd,
	0xd2,
	0x00,
	0x01,
	0x00,
	0x00,
	0x0b,
	0x6a,
	0x01,
	0x25,
	0x04,
	0x01,
	0x00,
	0x00,
	0xed,
	0x03,
	0x2b,
	0x43,
	0x08,
	0x01,
	0x00,
	0x00,
	0x0b,
	0x62,
	0x0b,
	0x6a,
	0x0c,
	0x01,
	0x00,
	0x00,
	0x6d,
	0x00,
	0x2b,
	0x43,
	0x10,
	0x01,
	0x00,
	0x00,
	0x0b,
	0x62,
	0x0b,
	0x6a,
	0x14,
	0x01,
	0x00,
	0x00,
	0xad,
	0x08,
	0xab,
	0x43,
	0x18,
	0x01,
	0x00,
	0x00,
	0x0b,
	0x62,
	0x0b,
	0x6a,
	0x1c,
	0x01,
	0x00,
	0x00,
	0x6d,
	0x08,
	0xab,
	0x43,
	0x20,
	0x01,
	0x00,
	0x00,
	0x0b,
	0x62,
	0x68,
	0x4d,
	0x24,
	0x01,
	0x00,
	0x00,
	0x69,
	0x4b,
	0x40,
	0x35,
	0x28,
	0x01,
	0x00,
	0x00,
	0x2b,
	0x60,
	0x6b,
	0x60,
	0x2c,
	0x01,
	0x00,
	0x00,
	0x00,
	0x23,
	0x0b,
	0x63,
	0x30,
	0x01,
	0x00,
	0x00,
	0x67,
	0x4e,
	0x35,
	0x1c,
	0x34,
	0x01,
	0x00,
	0x00,
	0x01,
	0x3d,
	0xfd,
	0xd2,
	0x38,
	0x01,
	0x00,
	0x00,
	0x0c,
	0x63,
	0x34,
	0x1c,
	0x3c,
	0x01,
	0x00,
	0x00,
	0x01,
	0x3c,
	0xfd,
	0xd2,
	0x40,
	0x01,
	0x00,
	0x00,
	0x64,
	0x4b,
	0x8b,
	0x61,
	0x44,
	0x01,
	0x00,
	0x00,
	0xcb,
	0x69,
	0xff,
	0x24,
	0x48,
	0x01,
	0x00,
	0x00,
	0x24,
	0x03,
	0xa3,
	0x43,
	0x4c,
	0x01,
	0x00,
	0x00,
	0x77,
	0x24,
	0x24,
	0x03,
	0x50,
	0x01,
	0x00,
	0x00,
	0x1b,
	0x19,
	0xcb,
	0x61,
	0x54,
	0x01,
	0x00,
	0x00,
	0x60,
	0x4b,
	0x0b,
	0x61,
	0x58,
	0x01,
	0x00,
	0x00,
	0x4a,
	0x62,
	0x01,
	0x24,
	0x5c,
	0x01,
	0x00,
	0x00,
	0xe4,
	0x02,
	0x21,
	0x1c,
	0x60,
	0x01,
	0x00,
	0x00,
	0x01,
	0x39,
	0xfd,
	0xd2,
	0x64,
	0x01,
	0x00,
	0x00,
	0x61,
	0x21,
	0x41,
	0x61,
	0x68,
	0x01,
	0x00,
	0x00,
	0xe1,
	0x21,
	0x41,
	0x61,
	0x6c,
	0x01,
	0x00,
	0x00,
	0x5b,
	0x49,
	0x0e,
	0x1c,
	0x70,
	0x01,
	0x00,
	0x00,
	0x01,
	0x3e,
	0xfd,
	0xd2,
	0x74,
	0x01,
	0x00,
	0x00,
	0x6f,
	0x23,
	0x43,
	0x61,
	0x78,
	0x01,
	0x00,
	0x00,
	0x05,
	0x1c,
	0xef,
	0x20,
	0x7c,
	0x01,
	0x00,
	0x00,
	0x68,
	0x61,
	0x58,
	0x4e,
	0x80,
	0x01,
	0x00,
	0x00,
	0x30,
	0x1c,
	0x01,
	0x38,
	0x84,
	0x01,
	0x00,
	0x00,
	0xfd,
	0xd2,
	0x70,
	0x20,
	0x88,
	0x01,
	0x00,
	0x00,
	0x68,
	0x61,
	0xf0,
	0x20,
	0x8c,
	0x01,
	0x00,
	0x00,
	0x68,
	0x61,
	0x30,
	0x1c,
	0x90,
	0x01,
	0x00,
	0x00,
	0x01,
	0x38,
	0xfd,
	0xd2,
	0x94,
	0x01,
	0x00,
	0x00,
	0x62,
	0x20,
	0x68,
	0x61,
	0x98,
	0x01,
	0x00,
	0x00,
	0xe2,
	0x20,
	0x68,
	0x61,
	0x9c,
	0x01,
	0x00,
	0x00,
	0x30,
	0x1c,
	0x01,
	0x38,
	0xa0,
	0x01,
	0x00,
	0x00,
	0xfd,
	0xd2,
	0x01,
	0x20,
	0xa4,
	0x01,
	0x00,
	0x00,
	0x40,
	0x04,
	0x28,
	0x62,
	0xa8,
	0x01,
	0x00,
	0x00,
	0x68,
	0x26,
	0x6e,
	0x61,
	0xac,
	0x01,
	0x00,
	0x00,
	0xe8,
	0x27,
	0x6f,
	0x61,
	0xb0,
	0x01,
	0x00,
	0x00,
	0x08,
	0x1c,
	0x01,
	0x38,
	0xb4,
	0x01,
	0x00,
	0x00,
	0xfd,
	0xd2,
	0x03,
	0x20,
	0xb8,
	0x01,
	0x00,
	0x00,
	0x00,
	0x04,
	0x28,
	0x62,
	0xbc,
	0x01,
	0x00,
	0x00,
	0x6e,
	0x61,
	0x6f,
	0x61,
	0xc0,
	0x01,
	0x00,
	0x00,
	0x08,
	0x1c,
	0x01,
	0x38,
	0xc4,
	0x01,
	0x00,
	0x00,
	0xfd,
	0xd2,
	0x47,
	0x48,
	0xc8,
	0x01,
	0x00,
	0x00,
	0x28,
	0x62,
	0x6e,
	0x61,
	0xcc,
	0x01,
	0x00,
	0x00,
	0x6f,
	0x61,
	0x08,
	0x1c,
	0xd0,
	0x01,
	0x00,
	0x00,
	0x01,
	0x38,
	0xfd,
	0xd2,
	0xd4,
	0x01,
	0x00,
	0x00,
	0xb1,
	0x20,
	0x00,
	0x01,
	0xd8,
	0x01,
	0x00,
	0x00,
	0x28,
	0x62,
	0x6e,
	0x61,
	0xdc,
	0x01,
	0x00,
	0x00,
	0x6f,
	0x61,
	0x20,
	0x1c,
	0xe0,
	0x01,
	0x00,
	0x00,
	0x01,
	0x38,
	0xfd,
	0xd2,
	0xe4,
	0x01,
	0x00,
	0x00,
	0x2a,
	0x62,
	0x71,
	0x20,
	0xe8,
	0x01,
	0x00,
	0x00,
	0x68,
	0x61,
	0xf1,
	0x20,
	0xec,
	0x01,
	0x00,
	0x00,
	0x68,
	0x61,
	0x20,
	0x1c,
	0xf0,
	0x01,
	0x00,
	0x00,
	0x01,
	0x38,
	0xfd,
	0xd2,
	0xf4,
	0x01,
	0x00,
	0x00,
	0x2f,
	0x48,
	0x22,
	0x49,
	0xf8,
	0x01,
	0x00,
	0x00,
	0x26,
	0x38,
	0x88,
	0x61,
	0xfc,
	0x01,
	0x00,
	0x00,
	0x00,
	0x23,
	0x6b,
	0x61,
	0x00,
	0x02,
	0x00,
	0x00,
	0x20,
	0x1c,
	0x01,
	0x38,
	0x04,
	0x02,
	0x00,
	0x00,
	0xfd,
	0xd2,
	0x38,
	0x48,
	0x08,
	0x02,
	0x00,
	0x00,
	0x0f,
	0x21,
	0x09,
	0x07,
	0x0c,
	0x02,
	0x00,
	0x00,
	0xc8,
	0x60,
	0xf0,
	0xbd,
	0x10,
	0x02,
	0x00,
	0x00,
	0x14,
	0x23,
	0x58,
	0x43,
	0x14,
	0x02,
	0x00,
	0x00,
	0x41,
	0x1e,
	0x02,
	0x1c,
	0x18,
	0x02,
	0x00,
	0x00,
	0x08,
	0x1c,
	0x00,
	0x2a,
	0x1c,
	0x02,
	0x00,
	0x00,
	0xfa,
	0xd1,
	0x70,
	0x47,
	0x20,
	0x02,
	0x00,
	0x00,
	0x30,
	0xb5,
	0x32,
	0x4c,
	0x24,
	0x02,
	0x00,
	0x00,
	0x20,
	0x68,
	0x03,
	0x21,
	0x28,
	0x02,
	0x00,
	0x00,
	0x09,
	0x03,
	0x08,
	0x43,
	0x2c,
	0x02,
	0x00,
	0x00,
	0x20,
	0x60,
	0x01,
	0x20,
	0x30,
	0x02,
	0x00,
	0x00,
	0xff,
	0xf7,
	0xee,
	0xff,
	0x34,
	0x02,
	0x00,
	0x00,
	0x2d,
	0x4d,
	0x40,
	0x3d,
	0x38,
	0x02,
	0x00,
	0x00,
	0x28,
	0x6b,
	0x07,
	0x21,
	0x3c,
	0x02,
	0x00,
	0x00,
	0x09,
	0x02,
	0x88,
	0x43,
	0x40,
	0x02,
	0x00,
	0x00,
	0xff,
	0x39,
	0x01,
	0x39,
	0x44,
	0x02,
	0x00,
	0x00,
	0x40,
	0x18,
	0x28,
	0x63,
	0x48,
	0x02,
	0x00,
	0x00,
	0x01,
	0x20,
	0xff,
	0xf7,
	0x4c,
	0x02,
	0x00,
	0x00,
	0xe1,
	0xff,
	0x20,
	0x68,
	0x50,
	0x02,
	0x00,
	0x00,
	0x33,
	0x21,
	0x09,
	0x03,
	0x54,
	0x02,
	0x00,
	0x00,
	0x88,
	0x43,
	0x20,
	0x60,
	0x58,
	0x02,
	0x00,
	0x00,
	0x01,
	0x20,
	0xff,
	0xf7,
	0x5c,
	0x02,
	0x00,
	0x00,
	0xd9,
	0xff,
	0x28,
	0x6b,
	0x60,
	0x02,
	0x00,
	0x00,
	0x70,
	0x21,
	0x08,
	0x43,
	0x64,
	0x02,
	0x00,
	0x00,
	0x28,
	0x63,
	0x01,
	0x20,
	0x68,
	0x02,
	0x00,
	0x00,
	0xff,
	0xf7,
	0xd2,
	0xff,
	0x6c,
	0x02,
	0x00,
	0x00,
	0x30,
	0xbd,
	0x00,
	0xb5,
	0x70,
	0x02,
	0x00,
	0x00,
	0xff,
	0xf7,
	0xd6,
	0xff,
	0x74,
	0x02,
	0x00,
	0x00,
	0xff,
	0xf7,
	0xc8,
	0xfe,
	0x78,
	0x02,
	0x00,
	0x00,
	0x00,
	0xbd,
	0x00,
	0x00,
	0x7c,
	0x02,
	0x00,
	0x00,
	0x5f,
	0x00,
	0x00,
	0x80,
	0x80,
	0x02,
	0x00,
	0x00,
	0x00,
	0x07,
	0x00,
	0xf0,
	0x84,
	0x02,
	0x00,
	0x00,
	0xc0,
	0x00,
	0x00,
	0xf0,
	0x88,
	0x02,
	0x00,
	0x00,
	0x05,
	0x05,
	0x03,
	0x03,
	0x8c,
	0x02,
	0x00,
	0x00,
	0x01,
	0xfe,
	0x00,
	0x00,
	0x90,
	0x02,
	0x00,
	0x00,
	0x00,
	0x04,
	0x00,
	0xf0,
	0x94,
	0x02,
	0x00,
	0x00,
	0x0c,
	0x06,
	0x0e,
	0x05,
	0x98,
	0x02,
	0x00,
	0x00,
	0x00,
	0x06,
	0x00,
	0xf0,
	0x9c,
	0x02,
	0x00,
	0x00,
	0x04,
	0x0d,
	0x10,
	0x09,
	0xa0,
	0x02,
	0x00,
	0x00,
	0x13,
	0x05,
	0x24,
	0x04,
	0xa4,
	0x02,
	0x00,
	0x00,
	0x0f,
	0x40,
	0x00,
	0x00,
	0xa8,
	0x02,
	0x00,
	0x00,
	0x02,
	0x05,
	0x01,
	0x05,
	0xac,
	0x02,
	0x00,
	0x00,
	0x01,
	0x72,
	0x80,
	0x00,
	0xb0,
	0x02,
	0x00,
	0x00,
	0x08,
	0x06,
	0x0a,
	0x06,
	0xb4,
	0x02,
	0x00,
	0x00,
	0x05,
	0x05,
	0x00,
	0x00,
	0xb8,
	0x02,
	0x00,
	0x00,
	0x53,
	0x05,
	0x58,
	0x88,
	0xbc,
	0x02,
	0x00,
	0x00,
	0x04,
	0x14,
	0x0c,
	0x82,
	0xc0,
	0x02,
	0x00,
	0x00,
	0x08,
	0x20,
	0x10,
	0x24,
	0xc4,
	0x02,
	0x00,
	0x00,
	0x00,
	0x03,
	0x00,
	0xf0,
	0xc8,
	0x02,
	0x00,
	0x00,
	0xb8,
	0x88,
	0x00,
	0x00,
	0xcc,
	0x02,
	0x00,
	0x00,
	0x70,
	0x30,
	0x04,
	0x00,
	0xd0,
	0x02,
	0x00,
	0x00,
	0x50,
	0x4e,
	0x00,
	0x00,
	0xd4,
	0x02,
	0x00,
	0x00,
	0x09,
	0x70,
	0x57,
	0x01,
	0xd8,
	0x02,
	0x00,
	0x00,
	0x88,
	0x88,
	0x88,
	0x00,
	0xdc,
	0x02,
	0x00,
	0x00,
	0x70,
	0x1f,
	0x00,
	0x00,
	0xe0,
	0x02,
	0x00,
	0x00,
	0xc0,
	0x47,
	0x0c,
	0x00,
	0xe4,
	0x02,
	0x00,
	0x00,
	0x40,
	0x00,
	0x01,
	0x00,
	0xe8,
	0x02,
	0x00,
	0x00,
	0x01,
	0x11,
	0x00,
	0x00,
	0xec,
	0x02,
	0x00,
	0x00,
	0x40,
	0x20,
	0x00,
	0x80,
	0x07,
	0xa1,
	0x26,
	0xda,
};
