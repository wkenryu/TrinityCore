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

#include "GameUtilitiesService.h"
#include "Session.h"

Battlenet::Service::GameUtilities::GameUtilities(Session* session) : GameUtilitiesServiceBase(session)
{
}

void Battlenet::Service::GameUtilities::ProcessClientRequest(pb::RpcController* /*controller*/, game_utilities::ClientRequest const* request, game_utilities::ClientResponse* response, pb::Closure* /*done*/)
{
    _session->HandleProcessClientRequest(request, response);
}

void Battlenet::Service::GameUtilities::GetAllValuesForAttribute(pb::RpcController* /*controller*/, game_utilities::GetAllValuesForAttributeRequest const* request, game_utilities::GetAllValuesForAttributeResponse* response, pb::Closure* /*done*/)
{
    _session->HandleGetAllValuesForAttribute(request, response);
}
