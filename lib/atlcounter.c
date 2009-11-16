/*
 * Copyright 2017, Allied Telesis Labs New Zealand, Ltd
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 *
 */

#include "atlcounter.h"
#include "syslog-names.h"
#include "logmsg/logmsg.h"
#include "cntrd_app_defines.h"
#include "cntrd_app_api.h"

void *cntrSyslogReceivedTotalPt = NULL;
void *cntrSyslogReceivedPri[8] = { };
void *syslogCntrHandle = NULL;

void atl_counter_increment_message (LogMessage *msg)
{
	if (syslogCntrHandle)
	{
		cntrd_app_inc_ctr(syslogCntrHandle, cntrSyslogReceivedTotalPt);
		cntrd_app_inc_ctr(syslogCntrHandle, cntrSyslogReceivedPri[LOG_PRI(msg->pri)]);
	}
}

void atl_counter_init()
{
	int retVal;
	gint cnt;
	gchar cntrd_name[21];

	retVal = cntrd_app_init_app("syslog-ng", CNTRD_APP_PERSISTENT,
			(void **) &syslogCntrHandle);

	if (retVal != CNTRD_APP_SUCCESS && retVal != CNTRD_APP_ERR_EXISTS)
	{
		syslogCntrHandle = NULL;
		return;
	}

	cntrd_app_register_ctr_in_group(syslogCntrHandle, "Total Received",
			&cntrSyslogReceivedTotalPt);

	for (cnt = 0; cnt < 8; cnt++)
	{
		g_snprintf(cntrd_name, sizeof(cntrd_name), "Total Received P%d", cnt);
		cntrd_app_register_ctr_in_group(syslogCntrHandle, cntrd_name,
				&(cntrSyslogReceivedPri[cnt]));
	}
}

void atl_counter_deinit()
{
	if (syslogCntrHandle != NULL)
	{
		cntrd_app_unInit_app(&syslogCntrHandle, CNTRD_APP_PERSISTENT);
		syslogCntrHandle = NULL;
	}
}
