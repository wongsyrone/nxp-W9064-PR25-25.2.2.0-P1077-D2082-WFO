/** @file fifo.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2019 NXP
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

#ifndef __FIFO_H__
#define __FIFO_H__

void fifo_init(void);

int fifo_ready(void);

int h2t_fifo_in(void *buf, unsigned int len);

int h2t_fifo_peek(void *buf, unsigned int buf_size);

int h2t_fifo_out(void *buf, unsigned int buf_size);

int t2h_fifo_in(void *buf, unsigned len);

int t2h_fifo_peek(void *buf, unsigned buf_size);

int t2h_fifo_out(void *buf, unsigned buf_size);

#endif /* __FIFO_H__ */
