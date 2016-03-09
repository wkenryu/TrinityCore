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

#ifndef GameUtilitiesServiceService_h__
#define GameUtilitiesServiceService_h__

#include "Common.h"
#include "ServiceBase.h"
#include "game_utilities_service.pb.h"

namespace pb = google::protobuf;

namespace Battlenet
{
    class Session;

    namespace Service
    {
        class GameUtilities : public ServiceBase<game_utilities::GameUtilitiesService>
        {
            typedef ServiceBase<game_utilities::GameUtilitiesService> GameUtilitiesServiceBase;

        public:
            typedef std::integral_constant<uint32, 0x3FC1274D> Hash;

            GameUtilities(Session* session);

            void ProcessClientRequest(pb::RpcController* controller, game_utilities::ClientRequest const* request, game_utilities::ClientResponse* response, pb::Closure* done) override;
            void GetAllValuesForAttribute(pb::RpcController* controller, game_utilities::GetAllValuesForAttributeRequest const* request, game_utilities::GetAllValuesForAttributeResponse* response, pb::Closure* done) override;
        };
    }
}

#endif // AccountService_h__
