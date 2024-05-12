/** @file trace.h
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
#undef TRACE_SYSTEM
#define TRACE_SYSTEM ap8x

#if !defined(_TRACE_AP8X) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_AP8X

#include <linux/tracepoint.h>
#include <linux/netdevice.h>

DECLARE_EVENT_CLASS(ap8x_dummy_template, TP_PROTO(int foo), TP_ARGS(foo), TP_STRUCT__entry(__field(int, foo)
		    ), TP_fast_assign(__entry->foo = foo;), TP_printk("foo=%d", __entry->foo)
    )

DECLARE_EVENT_CLASS(ap8x_skb_template, TP_PROTO(struct sk_buff *skb), TP_ARGS(skb), TP_STRUCT__entry(__field(void *, skbaddr)
												     __field(unsigned int, len)
												     __string(name, skb->dev->name)
		    ),
		    TP_fast_assign(__entry->skbaddr = skb;
				   __entry->len = skb->len;
				   __assign_str(name, skb->dev->name);),
		    TP_printk("dev=%s skbaddr=%p len=%u", __get_str(name), __entry->skbaddr, __entry->len)
    )

DECLARE_EVENT_CLASS(ap8x_dev_template, TP_PROTO(const struct net_device *dev), TP_ARGS(dev), TP_STRUCT__entry(__string(name, dev->name)
		    ), TP_fast_assign(__assign_str(name, dev->name);), TP_printk("dev=%s", __get_str(name))
    )

DEFINE_EVENT(ap8x_skb_template, wlDataTx, TP_PROTO(struct sk_buff *skb), TP_ARGS(skb)
    );

DEFINE_EVENT(ap8x_skb_template, wlDataTxHdl_inloop, TP_PROTO(struct sk_buff *skb), TP_ARGS(skb)
    );

DEFINE_EVENT(ap8x_skb_template, wlxmit, TP_PROTO(struct sk_buff *skb), TP_ARGS(skb)
    );

DEFINE_EVENT(ap8x_skb_template, _wlDataTx, TP_PROTO(struct sk_buff *skb), TP_ARGS(skb)
    );

DEFINE_EVENT(ap8x_skb_template, wlxmit_done_fail, TP_PROTO(struct sk_buff *skb), TP_ARGS(skb)
    );

DEFINE_EVENT(ap8x_skb_template, wlxmit_done_ok, TP_PROTO(struct sk_buff *skb), TP_ARGS(skb)
    );

DEFINE_EVENT(ap8x_skb_template, ieee80211_encap, TP_PROTO(struct sk_buff *skb), TP_ARGS(skb)
    );

DEFINE_EVENT(ap8x_skb_template, wlTxDone_begin, TP_PROTO(struct sk_buff *skb), TP_ARGS(skb)
    );

DEFINE_EVENT(ap8x_skb_template, wlTxDone_end, TP_PROTO(struct sk_buff *skb), TP_ARGS(skb)
    );

DEFINE_EVENT(ap8x_skb_template, wl_free_skb, TP_PROTO(struct sk_buff *skb), TP_ARGS(skb)
    );

DEFINE_EVENT(ap8x_skb_template, ieee80211_input, TP_PROTO(struct sk_buff *skb), TP_ARGS(skb)
    );

DEFINE_EVENT(ap8x_skb_template, ForwardFrame, TP_PROTO(struct sk_buff *skb), TP_ARGS(skb)
    );

DEFINE_EVENT(ap8x_skb_template, netif_receive_skb, TP_PROTO(struct sk_buff *skb), TP_ARGS(skb)
    );

DEFINE_EVENT(ap8x_skb_template, wl_receive_skb, TP_PROTO(struct sk_buff *skb), TP_ARGS(skb)
    );

DEFINE_EVENT(ap8x_dev_template, timer_routine, TP_PROTO(const struct net_device *dev), TP_ARGS(dev)
    );

DEFINE_EVENT(ap8x_dev_template, timer_routine_wlTxDone_begin, TP_PROTO(const struct net_device *dev), TP_ARGS(dev)
    );

DEFINE_EVENT(ap8x_dev_template, timer_routine_wlTxDone_end, TP_PROTO(const struct net_device *dev), TP_ARGS(dev)
    );

DEFINE_EVENT(ap8x_dev_template, wlDataTxHdl_begin, TP_PROTO(const struct net_device *dev), TP_ARGS(dev)
    );

DEFINE_EVENT(ap8x_dev_template, wlDataTxHdl_end, TP_PROTO(const struct net_device *dev), TP_ARGS(dev)
    );

DEFINE_EVENT(ap8x_dev_template, wlRecvHdlr, TP_PROTO(const struct net_device *dev), TP_ARGS(dev)
    );

DEFINE_EVENT(ap8x_dev_template, wlRecv_begin, TP_PROTO(const struct net_device *dev), TP_ARGS(dev)
    );

DEFINE_EVENT(ap8x_dev_template, wlRecv_end, TP_PROTO(const struct net_device *dev), TP_ARGS(dev)
    );

DEFINE_EVENT(ap8x_dummy_template, txdone_unlock_begin, TP_PROTO(int foo), TP_ARGS(foo)
    );

DEFINE_EVENT(ap8x_dummy_template, txdone_unlock_end, TP_PROTO(int foo), TP_ARGS(foo)
    );

TRACE_EVENT(wlTxDone_cond,
	    TP_PROTO(unsigned int txDoneTail,
		     unsigned int txDoneHead), TP_ARGS(txDoneTail, txDoneHead), TP_STRUCT__entry(__field(unsigned int, txDoneTail)
												 __field(unsigned int, txDoneHead)
	    ),
	    TP_fast_assign(__entry->txDoneTail = txDoneTail;
			   __entry->txDoneHead = txDoneHead;), TP_printk("txDoneTail=%u txDoneHead=%u", __entry->txDoneTail, __entry->txDoneHead)
    );

#endif				/* !_TRACE_AP8X || TRACE_HEADER_MULTI_READ */
/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace
#include <trace/define_trace.h>
