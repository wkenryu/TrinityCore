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

Battlenet::Service::GameUtilities::GameUtilities(Session* session) : game_utilities::GameUtilitiesService(session)
{
}

uint32 Battlenet::Service::GameUtilities::HandleProcessClientRequest(game_utilities::ClientRequest const* request, game_utilities::ClientResponse* response)
{
    return _session->HandleProcessClientRequest(request, response);
}

uint32 Battlenet::Service::GameUtilities::HandleGetAllValuesForAttribute(game_utilities::GetAllValuesForAttributeRequest const* request, game_utilities::GetAllValuesForAttributeResponse* response)
{
    return _session->HandleGetAllValuesForAttribute(request, response);
}
