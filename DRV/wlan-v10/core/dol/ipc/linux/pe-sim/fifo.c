/** @file fifo.c
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

#include <linux/kfifo.h>
#include "fifo.h"

/* fifo size in elements (bytes) */
#define FIFO_SIZE	2048

typedef
STRUCT_KFIFO_REC_1(FIFO_SIZE)
	fifo_rec;

     static fifo_rec h2t_fifo;
     spinlock_t h2t_lock;
     static fifo_rec t2h_fifo;
     spinlock_t t2h_lock;
     static bool _init = false;

     void fifo_init(void)
{
	INIT_KFIFO(h2t_fifo);
	spin_lock_init(&h2t_lock);
	INIT_KFIFO(t2h_fifo);
	spin_lock_init(&t2h_lock);
	_init = true;
}

int
fifo_ready(void)
{
	return (_init);
}

EXPORT_SYMBOL(fifo_ready);

int
h2t_fifo_in(void *buf, unsigned int len)
{
	int rc;

	spin_lock_bh(&h2t_lock);
	rc = kfifo_in(&h2t_fifo, buf, len);
	spin_unlock_bh(&h2t_lock);

	return rc;
}

EXPORT_SYMBOL(h2t_fifo_in);

int
h2t_fifo_peek(void *buf, unsigned int buf_size)
{
	int rc;

	spin_lock_bh(&h2t_lock);
	rc = kfifo_out_peek(&h2t_fifo, buf, buf_size);
	spin_unlock_bh(&h2t_lock);

	return rc;
}

EXPORT_SYMBOL(h2t_fifo_peek);

int
h2t_fifo_out(void *buf, unsigned int buf_size)
{
	int rc;

	spin_lock_bh(&h2t_lock);
	rc = kfifo_out(&h2t_fifo, buf, buf_size);
	spin_unlock_bh(&h2t_lock);

	return rc;
}

EXPORT_SYMBOL(h2t_fifo_out);

int
t2h_fifo_in(void *buf, unsigned len)
{
	int rc;

	spin_lock_bh(&t2h_lock);
	rc = kfifo_in(&t2h_fifo, buf, len);
	spin_unlock_bh(&t2h_lock);

	return rc;
}

EXPORT_SYMBOL(t2h_fifo_in);

int
t2h_fifo_peek(void *buf, unsigned buf_size)
{
	int rc;

	spin_lock_bh(&t2h_lock);
	rc = kfifo_out_peek(&t2h_fifo, buf, buf_size);
	spin_unlock_bh(&t2h_lock);

	return rc;
}

EXPORT_SYMBOL(t2h_fifo_peek);

int
t2h_fifo_out(void *buf, unsigned buf_size)
{
	int rc;

	spin_lock_bh(&t2h_lock);
	rc = kfifo_out(&t2h_fifo, buf, buf_size);
	spin_unlock_bh(&t2h_lock);

	return rc;
}

EXPORT_SYMBOL(t2h_fifo_out);
