/*
 * SpanDSP - a series of DSP components for telephony
 *
 * fax_modems.c - the analogue modem set for fax processing
 *
 * Written by Steve Underwood <steveu@coppice.org>
 *
 * Copyright (C) 2003, 2005, 2006, 2008 Steve Underwood
 *
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*! \file */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#if defined(HAVE_TGMATH_H)
#include <tgmath.h>
#endif
#if defined(HAVE_MATH_H)
#include <math.h>
#endif
#include "floating_fudge.h"
#include <assert.h>
#include <fcntl.h>
#include <time.h>
#if defined(LOG_FAX_AUDIO)
#include <unistd.h>
#endif

#include "spandsp/telephony.h"
#include "spandsp/logging.h"
#include "spandsp/bit_operations.h"
#include "spandsp/dc_restore.h"
#include "spandsp/queue.h"
#include "spandsp/power_meter.h"
#include "spandsp/complex.h"
#include "spandsp/tone_detect.h"
#include "spandsp/tone_generate.h"
#include "spandsp/async.h"
#include "spandsp/crc.h"
#include "spandsp/hdlc.h"
#include "spandsp/silence_gen.h"
#include "spandsp/fsk.h"
#include "spandsp/v29tx.h"
#include "spandsp/v29rx.h"
#include "spandsp/v27ter_tx.h"
#include "spandsp/v27ter_rx.h"
#include "spandsp/v17tx.h"
#include "spandsp/v17rx.h"
#include "spandsp/super_tone_rx.h"
#include "spandsp/modem_connect_tones.h"
#include "spandsp/fax_modems.h"

#include "spandsp/private/logging.h"
#include "spandsp/private/silence_gen.h"
#include "spandsp/private/fsk.h"
#include "spandsp/private/v17tx.h"
#include "spandsp/private/v17rx.h"
#include "spandsp/private/v27ter_tx.h"
#include "spandsp/private/v27ter_rx.h"
#include "spandsp/private/v29tx.h"
#include "spandsp/private/v29rx.h"
#include "spandsp/private/modem_connect_tones.h"
#include "spandsp/private/hdlc.h"
#include "spandsp/private/fax_modems.h"

#define HDLC_FRAMING_OK_THRESHOLD               5

static void fax_modems_hdlc_accept(void *user_data, const uint8_t *msg, int len, int ok)
{
    fax_modems_state_t *s;

    s = (fax_modems_state_t *) user_data;
    if (ok)
        s->rx_frame_received = TRUE;
    if (s->hdlc_accept)
        s->hdlc_accept(s->hdlc_accept_user_data, msg, len, ok);
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE_NONSTD(void) fax_modems_hdlc_tx_frame(void *user_data, const uint8_t *msg, int len)
{
    fax_modems_state_t *s;

    s = (fax_modems_state_t *) user_data;

    hdlc_tx_frame(&s->hdlc_tx, msg, len);
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE(void) fax_modems_hdlc_tx_flags(fax_modems_state_t *s, int flags)
{
    hdlc_tx_flags(&s->hdlc_tx, flags);
}
/*- End of function --------------------------------------------------------*/

static void v17_rx_status_handler(void *user_data, int status)
{
    fax_modems_state_t *s;

    s = (fax_modems_state_t *) user_data;
    switch (status)
    {
    case SIG_STATUS_TRAINING_SUCCEEDED:
        span_log(&s->logging, SPAN_LOG_FLOW, "Switching from V.17 + V.21 to V.17 (%.2fdBm0)\n", v17_rx_signal_power(&s->fast_modems.v17_rx));
        fax_modems_set_rx_handler(s, (span_rx_handler_t) &v17_rx, &s->fast_modems.v17_rx, (span_rx_fillin_handler_t) &v17_rx_fillin, &s->fast_modems.v17_rx);
        v17_rx_set_modem_status_handler(&s->fast_modems.v17_rx, NULL, s);
        break;
    }
    /*endswitch*/
    s->fast_modems.v17_rx.put_bit(s->fast_modems.v17_rx.put_bit_user_data, status);
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE_NONSTD(int) fax_modems_v17_v21_rx(void *user_data, const int16_t amp[], int len)
{
    fax_modems_state_t *s;

    s = (fax_modems_state_t *) user_data;
    v17_rx(&s->fast_modems.v17_rx, amp, len);
    fsk_rx(&s->v21_rx, amp, len);
    if (s->rx_frame_received)
    {
        /* We have received something, and the fast modem has not trained. We must be receiving valid V.21 */
        span_log(&s->logging, SPAN_LOG_FLOW, "Switching from V.17 + V.21 to V.21 (%.2fdBm0)\n", fsk_rx_signal_power(&s->v21_rx));
        fax_modems_set_rx_handler(s, (span_rx_handler_t) &fsk_rx, &s->v21_rx, (span_rx_fillin_handler_t) &fsk_rx_fillin, &s->v21_rx);
    }
    /*endif*/
    return 0;
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE_NONSTD(int) fax_modems_v17_v21_rx_fillin(void *user_data, int len)
{
    fax_modems_state_t *s;

    s = (fax_modems_state_t *) user_data;
    v17_rx_fillin(&s->fast_modems.v17_rx, len);
    fsk_rx_fillin(&s->v21_rx, len);
    return 0;
}
/*- End of function --------------------------------------------------------*/

static void v27ter_rx_status_handler(void *user_data, int status)
{
    fax_modems_state_t *s;

    s = (fax_modems_state_t *) user_data;
    switch (status)
    {
    case SIG_STATUS_TRAINING_SUCCEEDED:
        span_log(&s->logging, SPAN_LOG_FLOW, "Switching from V.27ter + V.21 to V.27ter (%.2fdBm0)\n", v27ter_rx_signal_power(&s->fast_modems.v27ter_rx));
        fax_modems_set_rx_handler(s, (span_rx_handler_t) &v27ter_rx, &s->fast_modems.v27ter_rx, (span_rx_fillin_handler_t) &v27ter_rx_fillin, &s->fast_modems.v27ter_rx);
        v27ter_rx_set_modem_status_handler(&s->fast_modems.v27ter_rx, NULL, s);
        break;
    }
    /*endswitch*/
    s->fast_modems.v27ter_rx.put_bit(s->fast_modems.v27ter_rx.put_bit_user_data, status);
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE_NONSTD(int) fax_modems_v27ter_v21_rx(void *user_data, const int16_t amp[], int len)
{
    fax_modems_state_t *s;

    s = (fax_modems_state_t *) user_data;
    v27ter_rx(&s->fast_modems.v27ter_rx, amp, len);
    fsk_rx(&s->v21_rx, amp, len);
    if (s->rx_frame_received)
    {
        /* We have received something, and the fast modem has not trained. We must be receiving valid V.21 */
        span_log(&s->logging, SPAN_LOG_FLOW, "Switching from V.27ter + V.21 to V.21 (%.2fdBm0)\n", fsk_rx_signal_power(&s->v21_rx));
        fax_modems_set_rx_handler(s, (span_rx_handler_t) &fsk_rx, &s->v21_rx, (span_rx_fillin_handler_t) &fsk_rx_fillin, &s->v21_rx);
    }
    /*endif*/
    return 0;
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE_NONSTD(int) fax_modems_v27ter_v21_rx_fillin(void *user_data, int len)
{
    fax_modems_state_t *s;

    s = (fax_modems_state_t *) user_data;
    v27ter_rx_fillin(&s->fast_modems.v27ter_rx, len);
    fsk_rx_fillin(&s->v21_rx, len);
    return 0;
}
/*- End of function --------------------------------------------------------*/

static void v29_rx_status_handler(void *user_data, int status)
{
    fax_modems_state_t *s;

    s = (fax_modems_state_t *) user_data;
    switch (status)
    {
    case SIG_STATUS_TRAINING_SUCCEEDED:
        span_log(&s->logging, SPAN_LOG_FLOW, "Switching from V.29 + V.21 to V.29 (%.2fdBm0)\n", v29_rx_signal_power(&s->fast_modems.v29_rx));
        fax_modems_set_rx_handler(s, (span_rx_handler_t) &v29_rx, &s->fast_modems.v29_rx, (span_rx_fillin_handler_t) &v29_rx_fillin, &s->fast_modems.v29_rx);
        v29_rx_set_modem_status_handler(&s->fast_modems.v29_rx, NULL, s);
        break;
    }
    /*endswitch*/
    s->fast_modems.v29_rx.put_bit(s->fast_modems.v29_rx.put_bit_user_data, status);
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE_NONSTD(int) fax_modems_v29_v21_rx(void *user_data, const int16_t amp[], int len)
{
    fax_modems_state_t *s;

    s = (fax_modems_state_t *) user_data;
    v29_rx(&s->fast_modems.v29_rx, amp, len);
    fsk_rx(&s->v21_rx, amp, len);
    if (s->rx_frame_received)
    {
        /* We have received something, and the fast modem has not trained. We must be receiving valid V.21 */
        span_log(&s->logging, SPAN_LOG_FLOW, "Switching from V.29 + V.21 to V.21 (%.2fdBm0)\n", fsk_rx_signal_power(&s->v21_rx));
        fax_modems_set_rx_handler(s, (span_rx_handler_t) &fsk_rx, &s->v21_rx, (span_rx_fillin_handler_t) &fsk_rx_fillin, &s->v21_rx);
    }
    /*endif*/
    return 0;
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE_NONSTD(int) fax_modems_v29_v21_rx_fillin(void *user_data, int len)
{
    fax_modems_state_t *s;

    s = (fax_modems_state_t *) user_data;
    v29_rx_fillin(&s->fast_modems.v29_rx, len);
    fsk_rx_fillin(&s->v21_rx, len);
    return 0;
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE(void) fax_modems_start_slow_modem(fax_modems_state_t *s, int which)
{
    switch (which)
    {
    case FAX_MODEM_V21_RX:
        fsk_rx_init(&s->v21_rx, &preset_fsk_specs[FSK_V21CH2], FSK_FRAME_MODE_SYNC, (put_bit_func_t) hdlc_rx_put_bit, &s->hdlc_rx);
        fsk_rx_signal_cutoff(&s->v21_rx, -39.09f);
        //fax_modems_set_rx_handler(s, (span_rx_handler_t) &fsk_rx, &s->v21_rx, (span_rx_fillin_handler_t) &fsk_rx_fillin, &s->v21_rx);
        s->rx_frame_received = FALSE;
        break;
    case FAX_MODEM_V21_TX:
        fsk_tx_init(&s->v21_tx, &preset_fsk_specs[FSK_V21CH2], (get_bit_func_t) hdlc_tx_get_bit, &s->hdlc_tx);
        break;
    }
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE(void) fax_modems_start_fast_modem(fax_modems_state_t *s, int which, int bit_rate, int short_train, int hdlc_mode)
{
    put_bit_func_t put_bit;
    get_bit_func_t get_bit;
    void *get_bit_user_data;
    void *put_bit_user_data;

    s->bit_rate = bit_rate;
    if (hdlc_mode)
    {
        get_bit = (get_bit_func_t) hdlc_tx_get_bit;
        get_bit_user_data = (void *) &s->hdlc_tx;
        put_bit = (put_bit_func_t) hdlc_rx_put_bit;
        put_bit_user_data = (void *) &s->hdlc_rx;
    }
    else
    {
        get_bit = s->get_bit;
        get_bit_user_data = s->get_bit_user_data;
        put_bit = s->put_bit;
        put_bit_user_data = s->put_bit_user_data;
    }
    /*endif*/

    /* If we change modems we need to do a complete reinitialisation of the modem, because
       the modems use overlapping memory. */
    if (s->fast_modem != which)
    {
        s->current_rx_type = which;
        s->short_train = FALSE;
        s->fast_modem = which;
        if (hdlc_mode)
            s->rx_frame_received = FALSE;
        switch (s->fast_modem)
        {
        case FAX_MODEM_V27TER_RX:
            v27ter_rx_init(&s->fast_modems.v27ter_rx, s->bit_rate, put_bit, put_bit_user_data);
            v27ter_rx_set_modem_status_handler(&s->fast_modems.v27ter_rx, v27ter_rx_status_handler, s);
            fax_modems_set_rx_handler(s, (span_rx_handler_t) &fax_modems_v27ter_v21_rx, s, (span_rx_fillin_handler_t) &fax_modems_v27ter_v21_rx_fillin, s);
            break;
        case FAX_MODEM_V29_RX:
            v29_rx_init(&s->fast_modems.v29_rx, s->bit_rate, put_bit, put_bit_user_data);
            v29_rx_signal_cutoff(&s->fast_modems.v29_rx, -45.5f);
            v29_rx_set_modem_status_handler(&s->fast_modems.v29_rx, v29_rx_status_handler, s);
            fax_modems_set_rx_handler(s, (span_rx_handler_t) &fax_modems_v29_v21_rx, s, (span_rx_fillin_handler_t) &fax_modems_v29_v21_rx_fillin, s);
            break;
        case FAX_MODEM_V17_RX:
            v17_rx_init(&s->fast_modems.v17_rx, s->bit_rate, put_bit, put_bit_user_data);
            v17_rx_set_modem_status_handler(&s->fast_modems.v17_rx, v17_rx_status_handler, s);
            fax_modems_set_rx_handler(s, (span_rx_handler_t) &fax_modems_v17_v21_rx, s, (span_rx_fillin_handler_t) &fax_modems_v17_v21_rx_fillin, s);
            break;
        case FAX_MODEM_V27TER_TX:
            v27ter_tx_init(&s->fast_modems.v27ter_tx, s->bit_rate, s->use_tep, get_bit, get_bit_user_data);
            fax_modems_set_tx_handler(s, (span_tx_handler_t) &v27ter_tx, &s->fast_modems.v27ter_tx);
            fax_modems_set_next_tx_handler(s, (span_tx_handler_t) NULL, NULL);
            break;
        case FAX_MODEM_V29_TX:
            v29_tx_init(&s->fast_modems.v29_tx, s->bit_rate, s->use_tep, get_bit, get_bit_user_data);
            fax_modems_set_tx_handler(s, (span_tx_handler_t) &v29_tx, &s->fast_modems.v29_tx);
            fax_modems_set_next_tx_handler(s, (span_tx_handler_t) NULL, NULL);
            break;
        case FAX_MODEM_V17_TX:
            v17_tx_init(&s->fast_modems.v17_tx, s->bit_rate, s->use_tep, get_bit, get_bit_user_data);
            fax_modems_set_tx_handler(s, (span_tx_handler_t) &v17_tx, &s->fast_modems.v17_tx);
            fax_modems_set_next_tx_handler(s, (span_tx_handler_t) NULL, NULL);
            break;
        }
        /*endswitch*/
    }
    else
    {
        s->short_train = short_train;
        switch (s->fast_modem)
        {
        case FAX_MODEM_V27TER_RX:
            v27ter_rx_restart(&s->fast_modems.v27ter_rx, s->bit_rate, FALSE);
            v27ter_rx_set_put_bit(&s->fast_modems.v27ter_rx, put_bit, put_bit_user_data);
            v27ter_rx_set_modem_status_handler(&s->fast_modems.v27ter_rx, v27ter_rx_status_handler, s);
            fax_modems_set_rx_handler(s, (span_rx_handler_t) &fax_modems_v27ter_v21_rx, s, (span_rx_fillin_handler_t) &fax_modems_v27ter_v21_rx_fillin, s);
            break;
        case FAX_MODEM_V29_RX:
            v29_rx_restart(&s->fast_modems.v29_rx, s->bit_rate, FALSE);
            v29_rx_set_put_bit(&s->fast_modems.v29_rx, put_bit, put_bit_user_data);
            v29_rx_set_modem_status_handler(&s->fast_modems.v29_rx, v29_rx_status_handler, s);
            fax_modems_set_rx_handler(s, (span_rx_handler_t) &fax_modems_v29_v21_rx, s, (span_rx_fillin_handler_t) &fax_modems_v29_v21_rx_fillin, s);
            break;
        case FAX_MODEM_V17_RX:
            v17_rx_restart(&s->fast_modems.v17_rx, s->bit_rate, s->short_train);
            v17_rx_set_put_bit(&s->fast_modems.v17_rx, put_bit, put_bit_user_data);
            v17_rx_set_modem_status_handler(&s->fast_modems.v17_rx, v17_rx_status_handler, s);
            fax_modems_set_rx_handler(s, (span_rx_handler_t) &fax_modems_v17_v21_rx, s, (span_rx_fillin_handler_t) &fax_modems_v17_v21_rx_fillin, s);
            break;
        case FAX_MODEM_V27TER_TX:
            v27ter_tx_restart(&s->fast_modems.v27ter_tx, s->bit_rate, s->use_tep);
            v27ter_tx_set_get_bit(&s->fast_modems.v27ter_tx, get_bit, get_bit_user_data);
            fax_modems_set_tx_handler(s, (span_tx_handler_t) &v27ter_tx, &s->fast_modems.v27ter_tx);
            fax_modems_set_next_tx_handler(s, (span_tx_handler_t) NULL, NULL);
            break;
        case FAX_MODEM_V29_TX:
            v29_tx_restart(&s->fast_modems.v29_tx, s->bit_rate, s->use_tep);
            v29_tx_set_get_bit(&s->fast_modems.v29_tx, get_bit, get_bit_user_data);
            fax_modems_set_tx_handler(s, (span_tx_handler_t) &v29_tx, &s->fast_modems.v29_tx);
            fax_modems_set_next_tx_handler(s, (span_tx_handler_t) NULL, NULL);
            break;
        case FAX_MODEM_V17_TX:
            v17_tx_restart(&s->fast_modems.v17_tx, s->bit_rate, s->use_tep, s->short_train);
            v17_tx_set_get_bit(&s->fast_modems.v17_tx, get_bit, get_bit_user_data);
            fax_modems_set_tx_handler(s, (span_tx_handler_t) &v17_tx, &s->fast_modems.v17_tx);
            fax_modems_set_next_tx_handler(s, (span_tx_handler_t) NULL, NULL);
            break;
        }
        /*endswitch*/
    }
    /*endif*/
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE(void) fax_modems_set_put_bit(fax_modems_state_t *s, put_bit_func_t put_bit, void *user_data)
{
    s->put_bit = put_bit;
    s->put_bit_user_data = user_data;
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE(void) fax_modems_set_get_bit(fax_modems_state_t *s, get_bit_func_t get_bit, void *user_data)
{
    s->get_bit = get_bit;
    s->get_bit_user_data = user_data;
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE(void) fax_modems_set_rx_handler(fax_modems_state_t *s,
                                             span_rx_handler_t rx_handler,
                                             void *rx_user_data,
                                             span_rx_fillin_handler_t rx_fillin_handler,
                                             void *rx_fillin_user_data)
{
    if (s->deferred_rx_handler_updates)
    {
        /* Only update the actual handlers if they are not currently sidelined to dummy targets */
        if (s->rx_handler != span_dummy_rx)
            s->rx_handler = rx_handler;
        /*endif*/
        s->base_rx_handler = rx_handler;

        if (s->rx_fillin_handler != span_dummy_rx_fillin)
            s->rx_fillin_handler = rx_fillin_handler;
        /*endif*/
        s->base_rx_fillin_handler = rx_fillin_handler;
    }
    else
    {
        s->rx_handler = rx_handler;
        s->rx_fillin_handler = rx_fillin_handler;
    }
    /*endif*/
    s->rx_user_data = rx_user_data;
    s->rx_fillin_user_data = rx_fillin_user_data;
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE(void) fax_modems_set_rx_active(fax_modems_state_t *s, int active)
{
    s->rx_handler = (active)  ?  s->base_rx_handler  :  span_dummy_rx;
    s->rx_fillin_handler = (active)  ?  s->base_rx_fillin_handler  :  span_dummy_rx_fillin;
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE(void) fax_modems_set_tx_handler(fax_modems_state_t *s, span_tx_handler_t handler, void *user_data)
{
    s->tx_handler = handler;
    s->tx_user_data = user_data;
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE(void) fax_modems_set_next_tx_handler(fax_modems_state_t *s, span_tx_handler_t handler, void *user_data)
{
    s->next_tx_handler = handler;
    s->next_tx_user_data = user_data;
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE(void) fax_modems_set_tep_mode(fax_modems_state_t *s, int use_tep)
{
    s->use_tep = use_tep;
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE(logging_state_t *) fax_modems_get_logging_state(fax_modems_state_t *s)
{
    return &s->logging;
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE(int) fax_modems_restart(fax_modems_state_t *s)
{
    return 0;
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE(fax_modems_state_t *) fax_modems_init(fax_modems_state_t *s,
                                                   int use_tep,
                                                   hdlc_frame_handler_t hdlc_accept,
                                                   hdlc_underflow_handler_t hdlc_tx_underflow,
                                                   put_bit_func_t non_ecm_put_bit,
                                                   get_bit_func_t non_ecm_get_bit,
                                                   tone_report_func_t tone_callback,
                                                   void *user_data)
{
    if (s == NULL)
    {
        if ((s = (fax_modems_state_t *) malloc(sizeof(*s))) == NULL)
            return NULL;
    }
    /*endif*/
    memset(s, 0, sizeof(*s));
    s->use_tep = use_tep;

    modem_connect_tones_tx_init(&s->connect_tx, MODEM_CONNECT_TONES_FAX_CNG);
    if (tone_callback)
    {
        modem_connect_tones_rx_init(&s->connect_rx,
                                    MODEM_CONNECT_TONES_FAX_CNG,
                                    tone_callback,
                                    user_data);
    }
    /*endif*/
    span_log_init(&s->logging, SPAN_LOG_NONE, NULL);
    span_log_set_protocol(&s->logging, "FAX modems");

    dc_restore_init(&s->dc_restore);

    s->get_bit = non_ecm_get_bit;
    s->get_bit_user_data = user_data;
    s->put_bit = non_ecm_put_bit;
    s->put_bit_user_data = user_data;

    s->hdlc_accept = hdlc_accept;
    s->hdlc_accept_user_data = user_data;

    hdlc_rx_init(&s->hdlc_rx, FALSE, FALSE, HDLC_FRAMING_OK_THRESHOLD, fax_modems_hdlc_accept, s);
    hdlc_tx_init(&s->hdlc_tx, FALSE, 2, FALSE, hdlc_tx_underflow, user_data);

    fax_modems_start_slow_modem(s, FAX_MODEM_V21_RX);
    fsk_tx_init(&s->v21_tx, &preset_fsk_specs[FSK_V21CH2], (get_bit_func_t) hdlc_tx_get_bit, &s->hdlc_tx);

    silence_gen_init(&s->silence_gen, 0);

    s->rx_signal_present = FALSE;
    s->rx_handler = (span_rx_handler_t) &span_dummy_rx;
    s->rx_fillin_handler = (span_rx_fillin_handler_t) &span_dummy_rx;
    s->rx_user_data = NULL;
    s->rx_fillin_user_data = NULL;
    s->tx_handler = (span_tx_handler_t) &silence_gen;
    s->tx_user_data = &s->silence_gen;
    return s;
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE(int) fax_modems_release(fax_modems_state_t *s)
{
    return 0;
}
/*- End of function --------------------------------------------------------*/

SPAN_DECLARE(int) fax_modems_free(fax_modems_state_t *s)
{
    if (s)
        free(s);
    /*endif*/
    return 0;
}
/*- End of function --------------------------------------------------------*/
/*- End of file ------------------------------------------------------------*/
