/*
 * Copyright (C) 2008-2016 TrinityCore <http://www.trinitycore.org/>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "AuthenticationService.h"
#include "SessionManager.h"
#include "Session.h"

Battlenet::Service::Authentication::Authentication(Session* session) : authentication::AuthenticationService(session)
{
}

uint32 Battlenet::Service::Authentication::HandleLogon(authentication::LogonRequest const* request, NoData* /*respons*/)
{
    return _session->HandleLogon(request);
}

uint32 Battlenet::Service::Authentication::HandleVerifyWebCredentials(authentication::VerifyWebCredentialsRequest const* request, NoData* /*respons*/)
{
    return _session->HandleVerifyWebCredentials(request);
}
